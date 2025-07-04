// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC4626Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
using SafeERC20 for IERC20;

contract CustomVault is Initializable, UUPSUpgradeable, ERC4626Upgradeable, AccessControlUpgradeable, ReentrancyGuardUpgradeable {
    using Math for uint256;

    bytes32 public constant BACKEND_ROLE = keccak256("BACKEND_ROLE");
    bytes32 public constant PROTOCOL_ADMIN_ROLE = keccak256("PROTOCOL_ADMIN_ROLE");

    uint256 public MIN_EXCHANGE_RATE;

    struct WithdrawalRequest {
        uint256 assets;
        uint256 shares;
        address owner;
        address receiver;
        uint256 timestamp;
        bool claimed;
    }

    struct WithdrawalRequestView {
        uint256 requestId;
        uint256 assets;
        uint256 shares;
        address owner;
        address receiver;
        uint256 timestamp;
        bool claimed;
    }

    uint256 public redemptionPeriod;
    uint256 public exchangeRate; // scaled by 1e18
    uint256 public exchangeRateUpdateTime;
    uint256 public exchangeRateExpireInterval;
    uint256 public latestRequestId;
    uint256 public totalAssetsCap;
    uint256 public minDepositAmount;

    uint256 public totalWithdrawingAssets;
    uint256 public totalWithdrawingShares;

    mapping(uint256 => WithdrawalRequest) public withdrawalRequests;

    // --- Multisig Whitelisting related constants ---

    address[] public multisigSigners;
    uint256 public requiredApprovals;

    struct WhitelistChangeRequest {
        address target;
        bool allowTransfer;
        bool executed;
        uint256 approvalCount;
        mapping(address => bool) approvals;
    }
    mapping(address => bool) public isWhitelisted;
    mapping(uint256 => WhitelistChangeRequest) public whitelistChangeRequests;

    struct AssetsCapChangeRequest {
        uint256 target;
        uint256 approvalCount;
        mapping(address => bool) approvals;
    }
    AssetsCapChangeRequest public capChangeRequest;

    // --- Events ---

    event WithdrawalRequested(uint256 indexed id, address indexed owner, address receiver, uint256 shares, uint256 assets);
    event WithdrawalClaimed(uint256 indexed id, address indexed owner, address receiver, uint256 assets);

    event AssetWithdrawnByProtocol(address indexed addr, address token, uint256 amount);
    event MinDepositAmountChanged(uint256 oldMin, uint256 newMin);
    event RedemptionPeriodUpdated(uint256 oldPeriod, uint256 newPeriod);
    event ExchangeRateExpireIntervalUpdated(uint256 oldInterval, uint256 newInterval);
    event ExchangeRateUpdated(uint256 oldRate, uint256 newRate, uint256 timestamp);
    event WhitelistUpdated(address indexed addr, bool status);
    event AssetsCapUpdated(uint256 oldCap, uint256 newCap);

    // --- Modifiers ---

    modifier onlyWhitelisted(address to) {
        require(isWhitelisted[to], "Destination is not whitelisted!");
        _;
    }

    modifier onlyAdmin() {
        require(
            hasRole(PROTOCOL_ADMIN_ROLE, _msgSender()) ||
            hasRole(DEFAULT_ADMIN_ROLE, _msgSender()),
            "Not Authorized Admin"
        );
        _;
    }

    modifier onlyBackendAndAdmin() {
        require(
            hasRole(BACKEND_ROLE, _msgSender()) ||
            hasRole(PROTOCOL_ADMIN_ROLE, _msgSender()) ||
            hasRole(DEFAULT_ADMIN_ROLE, _msgSender()),
            "Not Authorized Admin"
        );
        _;
    }

    modifier onlyMultisigSigners() {
        require(isMultisigSigner(_msgSender()), "Not Authorized Multisig Signer");
        _;
    }

    modifier whenUpToDate() {
        require(exchangeRateUpdateTime + exchangeRateExpireInterval >= block.timestamp, "ExchangeRate is not up-to-date");
        _;
    }

    modifier whenUnderCap(uint256 assetsToAdd) {
        require(totalAssets() + assetsToAdd <= totalAssetsCap, "Vault Cap Reached");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _asset,
        string memory _name,
        string memory _symbol,
        address admin,
        address[] memory _multisigSigners
    ) public initializer {
        __ERC4626_init(IERC20Metadata(_asset));
        __ERC20_init(_name, _symbol);
        __AccessControl_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        // TEST PARAMETERS
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PROTOCOL_ADMIN_ROLE, admin);
        _grantRole(BACKEND_ROLE, admin);

        require(_multisigSigners.length > 0, "No admins");
        MIN_EXCHANGE_RATE = 5e17; // 0.5 test param
        exchangeRate = 1e18; // 1 share = 1 asset initially
        exchangeRateExpireInterval = 5 days;
        exchangeRateUpdateTime = block.timestamp;
        totalAssetsCap = 1000e6; // 1000 * (10 ** 6) for initial USDC cap for FUJI Testnet 
        minDepositAmount = 1e5; // 0.01 * (10 ** 6) for Testnet
        totalWithdrawingAssets = 0;
        totalWithdrawingShares = 0;
        redemptionPeriod = 15 minutes;
        requiredApprovals = _multisigSigners.length;
        for (uint i = 0; i < _multisigSigners.length; i++) {
            multisigSigners.push(_multisigSigners[i]);
        }
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyAdmin {}

    // --- Backend Setter Functions / Vault Exchange Rate Management ---

    /**
    * @notice Sets Redemption Period
    * @param newPeriod New redemption period  
    * @dev Only callable by admin
    */
    function setRedemptionPeriod(uint256 newPeriod) external onlyAdmin {
        emit RedemptionPeriodUpdated(redemptionPeriod, newPeriod);
        redemptionPeriod = newPeriod;
    }

    /**
    * @notice Sets exchangeRateExpireInterval
    * @param newInterval New Interval  
    * @dev When exchange rate expires, deposit/mint/requestWithdrawal stops
    *      Only callable by admin
    */
    function setExchangeRateExpireInterval(uint256 newInterval) external onlyAdmin {
        emit ExchangeRateExpireIntervalUpdated(exchangeRateExpireInterval, newInterval);
        exchangeRateExpireInterval = newInterval;
    }

    /**
    * @notice Sets minDepositAmount
    * @param newMin New minimum deposit amount  
    * @dev Only callable by admin
    */
    function setMinDepositAmount(uint256 newMin) external onlyAdmin {
        emit MinDepositAmountChanged(minDepositAmount, newMin);
        minDepositAmount = newMin;
    }

    /**
    * @notice Sets exchangeRate and exchangeRateUpdateTime
    * @param newRate New Interval  
    * @dev New rate can't go below 1 which is the initial value,
    *      Callable by updater or admin
    */
    function setExchangeRate(uint256 newRate) external onlyBackendAndAdmin {
        require(newRate >= MIN_EXCHANGE_RATE, "exchangeRate can not be below initial value of 1e18");
        exchangeRateUpdateTime = block.timestamp;
        emit ExchangeRateUpdated(exchangeRate, newRate, exchangeRateUpdateTime);
        exchangeRate = newRate;
    }

    // --- Multisig-Style Whitelist Management ---

    function isMultisigSigner(address addr) public view returns (bool) {
        for (uint i = 0; i < multisigSigners.length; i++) {
            if (multisigSigners[i] == addr) return true;
        }
        return false;
    }

    function whitelistChange(address target, bool allowTransfer, uint256 reqId) external onlyMultisigSigners {
        WhitelistChangeRequest storage req = whitelistChangeRequests[reqId];

        require(!req.approvals[_msgSender()], "Already approved");
        require(!req.executed, "Already executed");
        if (req.approvalCount == 0) {
            req.target = target;
            req.allowTransfer = allowTransfer;
        }

        req.approvals[_msgSender()] = true;
        req.approvalCount++;

        if (req.approvalCount >= requiredApprovals) {
            isWhitelisted[target] = allowTransfer;
            req.executed = true;
            emit WhitelistUpdated(target, allowTransfer);
        }
    }

    function assetsCapChange(uint256 newTarget) external onlyMultisigSigners {
        if (capChangeRequest.target != newTarget) {
            capChangeRequest.target = newTarget;
            capChangeRequest.approvalCount = 0;
            for (uint256 i = 0; i < multisigSigners.length; i++) {
                capChangeRequest.approvals[multisigSigners[i]] = false;
            }
        }

        require(!capChangeRequest.approvals[_msgSender()], "Already approved");
        capChangeRequest.approvals[_msgSender()] = true;
        capChangeRequest.approvalCount += 1;

        if (capChangeRequest.approvalCount >= requiredApprovals) {
            totalAssetsCap = capChangeRequest.target;
            capChangeRequest.approvalCount = 0;
            for (uint256 i = 0; i < multisigSigners.length; i++) {
                capChangeRequest.approvals[multisigSigners[i]] = false;
            }
        }
    }

    function protocolWithdraw(
        address _asset,
        uint256 amount,
        address destination
    ) external onlyWhitelisted(destination) onlyBackendAndAdmin nonReentrant {
        IERC20(_asset).safeTransfer(destination, amount);
        emit AssetWithdrawnByProtocol(destination, _asset, amount);
    }

    // --- Disable Native Token Transfers ---

    receive() external payable {
        revert("Native token transfers are not allowed");
    }

    fallback() external payable {
        revert("Native token transfers are not allowed");
    }

    // --- Overwritten Conversion Logic ---

    function _convertToAssets(uint256 shares, Math.Rounding rounding) internal view override virtual returns (uint256) {
        return shares.mulDiv(exchangeRate, 10 ** (18 + _decimalsOffset()), rounding);
    }

    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view override virtual returns (uint256) {
        return assets.mulDiv(10 ** (18 + _decimalsOffset()), exchangeRate, rounding);
    }

    // --- totalAssets Based on Exchange Rate ---

    function totalAssets() public view override returns (uint256) {
        return ((totalSupply() * exchangeRate) / 1e18) / (10 ** _decimalsOffset());
    }

    // --- Override deposit and mint functions to add whenUpToDate ---

    function mint(uint256 shares, address receiver) public override whenUpToDate whenUnderCap(previewMint(shares)) returns (uint256) {
        uint256 depositAmount = _convertToAssets(shares, Math.Rounding.Ceil);
        require(depositAmount >= minDepositAmount, "Amount is below minimum deposit");
        return super.mint(shares, receiver);
    }

    function deposit(uint256 assets, address receiver) public override whenUpToDate whenUnderCap(assets) returns (uint256) {
        require(assets >= minDepositAmount, "Amount is below minimum deposit");
        return super.deposit(assets, receiver);
    }

    // --- Override default withdraw/redeem flow of ERC4626 ---

    function withdraw(
        uint256 assets,
        address receiver,
        address owner
    ) public override returns (uint256) {
        revert("Withdrawals must go through requestWithdrawal()");
    }

    function redeem(
        uint256 shares,
        address receiver,
        address owner
    ) public override returns (uint256) {
        revert("Withdrawals must go through requestWithdrawal()");
    }

    function _withdraw(
        address caller,
        address receiver,
        address owner,
        uint256 assets,
        uint256 shares
    ) internal override virtual {
        revert("Withdrawals must go through requestWithdrawal()");
    }

    // --- Withdrawal Request & Redemption Flow ---

    /**
    * @notice Burns the caller's shares and allocates the corresponding assets for redemption to the specified receiver.
    * @param shares Amount of shares
    * @param receiver Receiver address of the assets
    * @dev The asset amount is computed based on the current exchange rate at the time of the request.
    *      exchangeRate must be up-to-date for successful request of withdrawal.
    */
    function requestWithdrawal(uint256 shares, address receiver) external whenUpToDate returns (uint256 requestId) {
        require(shares > 0, "Zero Shares");
        address owner = _msgSender(); // only token owner can withdraw
        uint256 maxShares = maxRedeem(owner);
        if (shares > maxShares) {
            revert ERC4626ExceededMaxRedeem(owner, shares, maxShares);
        }

        uint256 assets = previewRedeem(shares);

        _burn(owner, shares);

        requestId = latestRequestId + 1;
        withdrawalRequests[requestId] = WithdrawalRequest({
            assets: assets,
            shares: shares,
            owner: owner,
            receiver: receiver,
            timestamp: block.timestamp,
            claimed: false
        });

        latestRequestId = requestId;
        totalWithdrawingAssets += assets;
        totalWithdrawingShares += shares;

        emit WithdrawalRequested(requestId, owner, receiver, shares, assets);
    }

    /**
    * @notice Calls internal claim logic
    * @param requestId ID of the withdrawal request to claim
    */
    function claimWithdrawal(uint256 requestId) external {
        _claim(requestId, _msgSender());
    }

    /**
    * @notice Iterates over given multiple claim requests by calling internal claim logic
    * @param requestIds List of IDs of withdrawal requests to claim
    */
    function batchClaimWithdrawal(uint256[] calldata requestIds) external {
        for (uint256 i = 0; i < requestIds.length; ++i) {
            _claim(requestIds[i], _msgSender());
        }
    }

    /**
    * @notice Sends matured claimable assets that were allocated with requestWithdrawal to receiver.
    * @param requestId ID of the withdrawal request to claim
    * @param caller Caller address
    * @dev Should only be called after the redemption period; transfers assets to the receiver and finalizes the redemption.
    */
    function _claim(uint256 requestId, address caller) internal {
        WithdrawalRequest storage request = withdrawalRequests[requestId];
        require(caller == request.owner, "Caller is not the owner!");
        require(!request.claimed, "This request is already claimed!");
        require(block.timestamp >= request.timestamp + redemptionPeriod, "Redemption period not over!");

        request.claimed = true;
        IERC20(asset()).safeTransfer(request.receiver, request.assets);

        totalWithdrawingAssets -= request.assets;
        totalWithdrawingShares -= request.shares;
        emit WithdrawalClaimed(requestId, request.owner, request.receiver, request.assets);
    }

    // --- Views ---

    /**
    * @notice Returns withdrawalRequest
    * @param requestId ID of the withdrawalRequest
    */
    function getWithdrawalRequest(uint256 requestId) external view returns (WithdrawalRequest memory) {
        return withdrawalRequests[requestId];
    }

    /**
    * @notice Returns if the withdrawalRequest is claimable
    * @param requestId ID of the withdrawalRequest
    */
    function isClaimable(uint256 requestId) external view returns (bool) {
        WithdrawalRequest storage req = withdrawalRequests[requestId];
        return !req.claimed && block.timestamp >= req.timestamp + redemptionPeriod;
    }

    /**
    * @notice Returns remaining redemption period for withdrawal request
    * @param requestId ID of the withdrawalRequest
    * @dev If requestId is invalid or is claimable, returns 0
    */
    function timeUntilClaimable(uint256 requestId) external view returns (uint256) {
        WithdrawalRequest storage req = withdrawalRequests[requestId];
        if (block.timestamp >= req.timestamp + redemptionPeriod) {
            return 0;
        }
        return (req.timestamp + redemptionPeriod) - block.timestamp;
    }

    /**
    * @notice Returns most recent withdrawalRequests by filters
    * @param limit Amount of withdrawalRequest to get
    * @param ownerFilter Filters owner address or 0 address for no filter
    * @param receiverFilter Filters receiver address or 0 address for no filter
    * @param onlyUnclaimed Filters unclaimed records
    * @param onlyClaimable Filters claimable records
    */
    function filterWithdrawalRequests(
        uint256 limit,
        address ownerFilter,
        address receiverFilter,
        bool onlyUnclaimed,
        bool onlyClaimable
    ) external view returns (WithdrawalRequestView[] memory) 
    {
        uint256 found;
        WithdrawalRequestView[] memory temp = new WithdrawalRequestView[](limit);

        uint256 i = latestRequestId;
        while (i > 0 && found < limit) {
            WithdrawalRequest storage req = withdrawalRequests[i];
            i--;
            if (ownerFilter != address(0) && req.owner != ownerFilter) continue;
            if (receiverFilter != address(0) && req.receiver != receiverFilter) continue;
            if (onlyUnclaimed && req.claimed) continue;
            if (onlyClaimable && block.timestamp < req.timestamp + redemptionPeriod) continue;
            temp[found++] = WithdrawalRequestView({
                requestId: i+1,
                assets: req.assets,
                shares: req.shares,
                owner: req.owner,
                receiver: req.receiver,
                timestamp: req.timestamp,
                claimed: req.claimed
            });
        }

        // trim result
        WithdrawalRequestView[] memory result = new WithdrawalRequestView[](found);
        for (uint256 j = 0; j < found; j++) {
            result[j] = temp[j];
        }

        return result;
    }

    /**
    * @notice Returns the amount of assets that are redeeming
    * @dev Changing redemptionPeriod to a smaller timespan can cause this view to calculate wrong amounts
    */
    function totalWithdrawingAssetsInRedemptionPeriod() external view returns (uint256 _amount) {
        for (uint256 i = latestRequestId; i > 0; i--) {
            WithdrawalRequest storage req = withdrawalRequests[i];
            // Stop early if the request is already claimable (i.e. redemption period over)
            if (block.timestamp >= req.timestamp + redemptionPeriod) break;
            if (!req.claimed && block.timestamp >= req.timestamp && block.timestamp < req.timestamp + redemptionPeriod) {
                _amount += req.assets;
            }
        }
    }

    /**
    * @notice Returns the amount of assets that are requested withdrawal and not claimed for a time span
    * @param onlyUnclaimed Filter to exclude claimed records
    * @param startTimestamp Epoch start timestamp
    * @param endTimestamp Epoch end timestamp
    */
    function totalWithdrawingAssetsInRange(bool onlyUnclaimed, uint256 startTimestamp, uint256 endTimestamp) external view returns (uint256 _amount) {
        for (uint256 i = latestRequestId; i > 0; i--) {
            WithdrawalRequest storage req = withdrawalRequests[i];
            if (req.timestamp < startTimestamp) break;
            if (onlyUnclaimed && req.claimed) continue;
            if (req.timestamp >= startTimestamp && req.timestamp < endTimestamp) {
                _amount += req.assets;
            }
        }
    }

    /**
    * @notice Returns the amount of assets that is claimable at given time
    * @param timestamp Epoch timestamp
    */
    function totalClaimableAssetsAtTime(uint256 timestamp) external view returns (uint256 _amount) {
        _amount = totalWithdrawingAssets;
        for (uint256 i = latestRequestId; i > 0; i--) {
            WithdrawalRequest storage req = withdrawalRequests[i];
            if (req.claimed) continue;
            if (timestamp < req.timestamp + redemptionPeriod) {
                _amount -= req.assets;
            }
        }
    }
}

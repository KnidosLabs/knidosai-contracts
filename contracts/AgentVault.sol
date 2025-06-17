// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
using SafeERC20 for IERC20;

contract CustomVault is ERC4626, AccessControl, ReentrancyGuard {
    using Math for uint256;

    bytes32 public constant EXCHANGE_RATE_UPDATER_ROLE = keccak256("EXCHANGE_RATE_UPDATER_ROLE");
    bytes32 public constant PROTOCOL_ADMIN_ROLE = keccak256("PROTOCOL_ADMIN_ROLE");

    struct WithdrawalRequest {
        uint256 assets;
        uint256 shares;
        address owner;
        address receiver;
        uint256 timestamp;
        bool claimed;
    }

    uint256 public redemptionPeriod = 1 minutes;
    uint256 public exchangeRate; // scaled by 1e18
    uint256 public exchangeRateUpdateTime = 0;
    uint256 public exchangeRateExpireInterval = 10 minutes;
    uint256 public latestRequestId;

    uint256 public totalClaimingAssets = 0;
    uint256 public totalClaimingShares = 0;

    mapping(uint256 => WithdrawalRequest) public withdrawalRequests;

    // --- Multisig Whitelisting related constants ---

    address[] public withdrawalSigners;
    uint256 public requiredApprovals = 2;

    struct WhitelistChangeRequest {
        address target;
        bool allowTransfer;
        bool executed;
        uint256 approvalCount;
        mapping(address => bool) approvals;
    }
    mapping(address => bool) public isWhitelisted;
    mapping(uint256 => WhitelistChangeRequest) public whitelistChangeRequests;

    // --- Events ---

    event WithdrawalRequested(uint256 indexed id, address indexed owner, address receiver, uint256 shares, uint256 assets);
    event WithdrawalClaimed(uint256 indexed id, address indexed owner, address receiver, uint256 assets);

    event RedemptionPeriodUpdated(uint256 oldPeriod, uint256 newPeriod);
    event ExchangeRateExpireIntervalUpdated(uint256 oldInterval, uint256 newInterval);
    event ExchangeRateUpdated(uint256 oldRate, uint256 newRate, uint256 timestamp);
    event WhitelistUpdated(address indexed addr, bool status);

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

    modifier onlyUpdaterOrAdmin() {
        require(
            hasRole(EXCHANGE_RATE_UPDATER_ROLE, _msgSender()) ||
            hasRole(PROTOCOL_ADMIN_ROLE, _msgSender()) ||
            hasRole(DEFAULT_ADMIN_ROLE, _msgSender()),
            "Not Authorized Updater or Admin"
        );
        _;
    }

    modifier onlyWithdrawalSigners() {
        require(isWithdrawalSigner(_msgSender()), "Not Authorized Withdrawal Signer");
        _;
    }

    modifier whenUpToDate() {
        require(exchangeRateUpdateTime + exchangeRateExpireInterval >= block.timestamp, "ExchangeRate is not up-to-date");
        _;
    }

    constructor(address _asset, address[] memory _withdrawalSigners) ERC20("HSKL LP Token", "HSKL-LP") ERC4626(IERC20Metadata(_asset)) {
        require(_withdrawalSigners.length > 0, "No admins");

        exchangeRate = 1e18; // 1 share = 1 asset initially

        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _grantRole(PROTOCOL_ADMIN_ROLE, _msgSender());
        _grantRole(EXCHANGE_RATE_UPDATER_ROLE, _msgSender());

        for (uint i = 0; i < _withdrawalSigners.length; i++) {
            withdrawalSigners.push(_withdrawalSigners[i]);
        }
    }

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
    * @notice Sets exchangeRate and exchangeRateUpdateTime
    * @param newRate New Interval  
    * @dev New rate can't go below 1 which is the initial value,
    *      Callable by updater or admin
    */
    function setExchangeRate(uint256 newRate) external onlyUpdaterOrAdmin() {
        require(newRate > 1e18, "exchangeRate can not be below initial value of 1e18");
        exchangeRateUpdateTime = block.timestamp;
        emit ExchangeRateUpdated(exchangeRate, newRate, exchangeRateUpdateTime);
        exchangeRate = newRate;
    }

    // --- Multisig-Style Whitelist Management ---

    function isWithdrawalSigner(address addr) public view returns (bool) {
        for (uint i = 0; i < withdrawalSigners.length; i++) {
            if (withdrawalSigners[i] == addr) return true;
        }
        return false;
    }

    function whitelistChange(address target, bool allowTransfer, uint256 reqId) external onlyWithdrawalSigners {
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

    function protocolWithdraw(
        address _asset,
        uint256 amount,
        address destination
    ) external onlyWhitelisted(destination) onlyWithdrawalSigners nonReentrant {
        IERC20(_asset).safeTransfer(destination, amount);
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

    // --- Override default withdraw/redeem flow of ERC4626 ---

    function withdraw(
        uint256 assets,
        address receiver,
        address owner
    ) public override returns (uint256) {
        revert("Withdrawals must go through requestWithdraw()");
    }

    function redeem(
        uint256 shares,
        address receiver,
        address owner
    ) public override returns (uint256) {
        revert("Withdrawals must go through requestWithdraw()");
    }

    function _withdraw(
        address caller,
        address receiver,
        address owner,
        uint256 assets,
        uint256 shares
    ) internal override virtual {
        revert("Withdrawals must go through requestWithdraw()");
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
        totalClaimingAssets += assets;
        totalClaimingShares += shares;

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

        totalClaimingAssets -= request.assets;
        totalClaimingShares -= request.shares;
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
    * @notice Returns most recent withdrawalRequest's by owner
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
    ) external view returns (WithdrawalRequest[] memory) 
    {
        uint256 found;
        WithdrawalRequest[] memory temp = new WithdrawalRequest[](limit);

        uint256 i = latestRequestId;
        while (i > 0 && found < limit) {
            i--;
            WithdrawalRequest storage req = withdrawalRequests[i];

            if (ownerFilter != address(0) && req.owner != ownerFilter) continue;
            if (receiverFilter != address(0) && req.receiver != receiverFilter) continue;
            if (onlyUnclaimed && req.claimed) continue;
            if (onlyClaimable && block.timestamp < req.timestamp + redemptionPeriod) continue;

            temp[found++] = req;
        }

        // trim result
        WithdrawalRequest[] memory result = new WithdrawalRequest[](found);
        for (uint256 j = 0; j < found; j++) {
            result[j] = temp[j];
        }

        return result;
    }
}

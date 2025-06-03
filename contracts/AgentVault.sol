// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC4626} from "./extensions/CustomERC4626.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";


contract CustomVault is ERC4626, AccessControl, ReentrancyGuard {
    using Math for uint256;

    struct WithdrawalRequest {
        uint256 assets;
        uint256 shares;
        address owner;
        uint64 timestamp;
        bool claimed;
    }

    uint256 public REDEMPTION_PERIOD = 1 minutes;
    uint256 public exchangeRate; // scaled by 1e18
    uint256 public exchangeRateUpdateTime = 0;
    uint256 public latestRequestId;

    uint256 public totalRedeemingAssets = 0;

    mapping(uint256 => WithdrawalRequest) public withdrawalRequests;


    bytes32 public constant EXCHANGE_RATE_UPDATER_ROLE = keccak256("EXCHANGE_RATE_UPDATER_ROLE");
    address[] public adminSigners;
    uint256 public requiredApprovals = 2;

    mapping(address => bool) public isWhitelisted;

    struct WhitelistChangeRequest {
        address target;
        bool approved;
        uint256 approvalCount;
        mapping(address => bool) approvals;
    }

    mapping(bytes32 => WhitelistChangeRequest) public whitelistChangeRequests;



    // --- Modifiers ---

    modifier onlyWhitelisted(address to) {
        require(isWhitelisted[to], "Destination is not whitelisted!");
        _;
    }

    modifier onlyUpdaterOrAdmin() {
        require(
            hasRole(EXCHANGE_RATE_UPDATER_ROLE, msg.sender) ||
            hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "Not updater or admin"
        );
        _;
    }

    modifier onlyAdminSigners() {
        require(isAdmin(msg.sender), "Caller is not admin signer");
        _;
    }

    constructor(address _asset, address[] memory _adminSigners) ERC20("HSKL LP Token", "HSKL-LP") ERC4626(IERC20Metadata(_asset)) {
        require(_adminSigners.length > 0, "No admins");

        exchangeRate = 1e18; // 1 share = 1 asset initially

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(EXCHANGE_RATE_UPDATER_ROLE, msg.sender);

        for (uint i = 0; i < _adminSigners.length; i++) {
            adminSigners.push(_adminSigners[i]);
        }
    }

    // --- Backend Setter Functions / Vault Exchange Rate Management ---

    function setRedemptionPeriod(uint256 newPeriod) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit RedemptionPeriodUpdated(REDEMPTION_PERIOD, newPeriod);
        REDEMPTION_PERIOD = newPeriod;
    }

    function setExchangeRate(uint256 newRate) external onlyUpdaterOrAdmin() {
        require(newRate > 0, "Rate must be positive");
        exchangeRateUpdateTime = block.timestamp;
        emit ExchangeRateUpdated(exchangeRate, newRate, exchangeRateUpdateTime);
        exchangeRate = newRate;
    }

    // --- Multisig-Style Whitelist Management ---

    function isAdmin(address addr) public view returns (bool) {
        for (uint i = 0; i < adminSigners.length; i++) {
            if (adminSigners[i] == addr) return true;
        }
        return false;
    }

    function proposeWhitelistChange(address target, bool approved) external onlyAdminSigners {
        bytes32 id = keccak256(abi.encodePacked(target, approved));
        WhitelistChangeRequest storage req = whitelistChangeRequests[id];

        require(!req.approvals[msg.sender], "Already approved");
        if (req.approvalCount == 0) {
            req.target = target;
            req.approved = approved;
        }

        req.approvals[msg.sender] = true;
        req.approvalCount++;

        if (req.approvalCount >= requiredApprovals) {
            isWhitelisted[target] = approved;
            delete whitelistChangeRequests[id];
            emit WhitelistUpdated(target, approved);
        }
    }

    function protocolWithdraw(address _asset, uint256 amount, address destination) external onlyWhitelisted(destination) onlyAdminSigners nonReentrant {
        require(IERC20(_asset).transfer(destination, amount), "Transfer failed");
    }


    // --- Overwritten Conversion Logic ---

    function _convertToAssets(uint256 shares, Math.Rounding rounding) internal view override virtual returns (uint256) {
        return shares.mulDiv(exchangeRate, 1e18, rounding);
    }

    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view override virtual returns (uint256) {
        return assets.mulDiv(1e18, exchangeRate, rounding);
    }

    // --- totalAssets Based on Exchange Rate ---

    function totalAssets() public view override returns (uint256) {
        return (totalSupply() * exchangeRate) / 1e18;
    }

    // --- Withdrawal Request Flow ---

    function withdraw(uint256 shares) external returns (uint256 requestId) {
        require(shares > 0, "Zero shares");
        uint256 assets = convertToAssets(shares);

        _burn(msg.sender, shares);

        requestId = latestRequestId + 1;
        withdrawalRequests[requestId] = WithdrawalRequest({
            assets: assets,
            shares: shares,
            owner: msg.sender,
            timestamp: uint64(block.timestamp),
            claimed: false
        });

        latestRequestId = requestId;
        totalRedeemingAssets += assets;

        emit WithdrawalRequested(requestId, msg.sender, shares, assets);
    }

    function redeem(uint256 requestId) external {
        _redeem(requestId, msg.sender);
    }

    function batchRedeem(uint256[] calldata requestIds) external {
        for (uint256 i = 0; i < requestIds.length; ++i) {
            _redeem(requestIds[i], msg.sender);
        }
    }

    function _redeem(uint256 requestId, address caller) internal {
        WithdrawalRequest storage request = withdrawalRequests[requestId];
        require(caller == request.owner, "Caller is not the owner!");
        require(!request.claimed, "This request is already claimed!");
        require(block.timestamp >= request.timestamp + REDEMPTION_PERIOD, "Redemption period not over!");

        request.claimed = true;
        require(IERC20(asset()).transfer(request.owner, request.assets), "Transfer failed");

        totalRedeemingAssets -= request.assets;

        emit WithdrawalClaimed(requestId, request.owner, request.assets);
    }

    // --- Views ---

    function getWithdrawalRequest(uint256 requestId) external view returns (WithdrawalRequest memory) {
        return withdrawalRequests[requestId];
    }

    // --- Events ---

    event WithdrawalRequested(uint256 indexed id, address indexed user, uint256 shares, uint256 assets);
    event WithdrawalClaimed(uint256 indexed id, address indexed user, uint256 assets);

    event RedemptionPeriodUpdated(uint256 oldPeriod, uint256 newPeriod);
    event ExchangeRateUpdated(uint256 oldRate, uint256 newRate, uint256 timestamp);
    event WhitelistUpdated(address indexed addr, bool status);
}

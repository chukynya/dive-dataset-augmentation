"""Generate DIVERSE solc-0.8-compatible tf-snippets for DoS, Bad-Randomness, and TOD.

0.8.x differences from 0.5.x:
- `msg.sender` is `address` (not `address payable`); must cast: `payable(msg.sender).transfer()`
- Non-payable `address` variables also need `payable(addr)` cast before .transfer()/.send()
- `.call{value: amount}("")` (new-style); `.call.value(amount)()` removed
- `block.difficulty` removed in 0.8.18 — use blockhash or keccak entropy instead
- String/bytes params need `memory` keyword
- `registry.length--` removed; use `.pop()`

Written to bugs/<Type>/v08/tf/ which the family-aware injector checks FIRST for v08 bases
(before falling back to bugs/<Type>/tf/). Without this file the v08 family gets only the 4
upstream SolidiFI defaults — causing the model to memorize those 4 bytecodes instead of
learning the vulnerability concept.

Same diversity and no-fingerprint rules as the other gen_* scripts.
"""
import os

SOLIDIFI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "SolidiFI")
BUGS = os.path.join(SOLIDIFI, "bugs")

# ---------------------------------------------------------------------------
# DoS (0.8 dialect) — unbounded operations / failed-call-blocks-everyone.
# Same archetypes as the 0.5 set; syntax updated for 0.8.
# ---------------------------------------------------------------------------
DOS = [
"""address payable[] public shareholders;
mapping(address => uint256) public dividend;
function addShareholder(address payable who, uint256 amount) public {
    shareholders.push(who);
    dividend[who] = amount;
}
function payDividends() public {
    for (uint256 i = 0; i < shareholders.length; i++) {
        shareholders[i].transfer(dividend[shareholders[i]]);
    }
}""",

"""address payable[] public refundList;
mapping(address => uint256) public owed;
function queueRefund(address payable who, uint256 amount) public {
    refundList.push(who);
    owed[who] += amount;
}
function refundEveryone() public {
    for (uint256 i = 0; i < refundList.length; i++) {
        refundList[i].transfer(owed[refundList[i]]);
        owed[refundList[i]] = 0;
    }
}""",

"""uint256[] public ledgerEntries;
function appendEntry(uint256 v) public {
    ledgerEntries.push(v);
}
function totalLedger() public view returns (uint256) {
    uint256 s = 0;
    for (uint256 i = 0; i < ledgerEntries.length; i++) {
        s += ledgerEntries[i];
    }
    return s;
}""",

"""address[] public subscribers;
function subscribe(address who) public {
    subscribers.push(who);
}
function notifyAll(bytes memory payload) public {
    for (uint256 i = 0; i < subscribers.length; i++) {
        (bool ok, ) = subscribers[i].call(payload);
        require(ok);
    }
}""",

"""address[] public trackedAccounts;
mapping(address => uint256) public trackedBalance;
function track(address who, uint256 bal) public {
    trackedAccounts.push(who);
    trackedBalance[who] = bal;
}
function purgeAll() public {
    for (uint256 i = 0; i < trackedAccounts.length; i++) {
        delete trackedBalance[trackedAccounts[i]];
    }
    delete trackedAccounts;
}""",

"""struct Withdrawal { address payable to; uint256 amount; }
Withdrawal[] public withdrawalQueue;
function enqueueWithdrawal(address payable to, uint256 amount) public {
    withdrawalQueue.push(Withdrawal(to, amount));
}
function processQueue() public {
    for (uint256 i = 0; i < withdrawalQueue.length; i++) {
        withdrawalQueue[i].to.transfer(withdrawalQueue[i].amount);
    }
}""",

"""uint256[] public scores;
function submitScore(uint256 s) public {
    scores.push(s);
    for (uint256 i = scores.length - 1; i > 0; i--) {
        if (scores[i] > scores[i - 1]) {
            uint256 tmp = scores[i];
            scores[i] = scores[i - 1];
            scores[i - 1] = tmp;
        }
    }
}""",

"""address payable[] public bidders;
mapping(address => uint256) public bidAmount;
function placeAuctionBid() public payable {
    bidders.push(payable(msg.sender));
    bidAmount[msg.sender] += msg.value;
}
function closeAuction() public {
    for (uint256 i = 0; i < bidders.length; i++) {
        bidders[i].transfer(bidAmount[bidders[i]]);
    }
}""",

"""address payable[] public airdropList;
function enrollAirdrop(address payable who) public {
    airdropList.push(who);
}
function runAirdrop(uint256 amountEach) public {
    for (uint256 i = 0; i < airdropList.length; i++) {
        airdropList[i].transfer(amountEach);
    }
}""",

"""address[] public pendingUsers;
mapping(address => bool) public settled;
function addPending(address who) public {
    pendingUsers.push(who);
}
function settleAll() public {
    for (uint256 i = 0; i < pendingUsers.length; i++) {
        require(!settled[pendingUsers[i]]);
        settled[pendingUsers[i]] = true;
    }
}""",

"""address[] public savers;
mapping(address => uint256) public principal;
function openAccount(address who, uint256 amount) public {
    savers.push(who);
    principal[who] = amount;
}
function accrueInterest() public {
    for (uint256 i = 0; i < savers.length; i++) {
        principal[savers[i]] = principal[savers[i]] * 105 / 100;
    }
}""",

"""uint256[] public registry;
function addToRegistry(uint256 v) public {
    registry.push(v);
}
function removeAt(uint256 index) public {
    for (uint256 i = index; i < registry.length - 1; i++) {
        registry[i] = registry[i + 1];
    }
    registry.pop();
}""",

"""address payable[] public payees;
function addPayee(address payable who) public {
    payees.push(who);
}
function batchPay(uint256 amount) public {
    for (uint256 i = 0; i < payees.length; i++) {
        require(payees[i].send(amount));
    }
}""",

"""address[] public voters;
function castVote() public {
    voters.push(msg.sender);
}
function tallyVotes() public view returns (uint256) {
    uint256 count = 0;
    for (uint256 i = 0; i < voters.length; i++) {
        if (voters[i] != address(0)) {
            count++;
        }
    }
    return count;
}""",

"""address[] public members;
function joinMembers() public {
    members.push(msg.sender);
}
function rewardMembers() public {
    for (uint256 i = 0; i < members.length; i++) {
        (bool ok, ) = members[i].call{value: 1}("");
        require(ok);
    }
}""",

"""mapping(uint256 => address) public tokenOwner;
uint256 public totalMinted;
function batchMint(uint256 count) public {
    for (uint256 i = 0; i < count; i++) {
        tokenOwner[totalMinted] = msg.sender;
        totalMinted++;
    }
}""",
]

# ---------------------------------------------------------------------------
# Bad Randomness (0.8 dialect).
# block.difficulty removed in 0.8.18 — snippet 6 uses blockhash entropy instead.
# msg.sender.transfer() needs payable() cast in 0.8.
# ---------------------------------------------------------------------------
BAD_RANDOMNESS = [
"""address payable[] public lotteryPlayers;
uint256 public lotteryPot;
function joinLottery() public payable {
    lotteryPlayers.push(payable(msg.sender));
    lotteryPot += msg.value;
}
function drawLotteryWinner() public {
    uint256 idx = uint256(blockhash(block.number - 1)) % lotteryPlayers.length;
    lotteryPlayers[idx].transfer(lotteryPot);
    lotteryPot = 0;
}""",

"""mapping(address => uint256) public coinflipStake;
function placeCoinflip() public payable {
    coinflipStake[msg.sender] = msg.value;
}
function resolveCoinflip() public {
    if (block.timestamp % 2 == 0) {
        payable(msg.sender).transfer(coinflipStake[msg.sender] * 2);
    }
    coinflipStake[msg.sender] = 0;
}""",

"""uint256 public lastRoll;
function rollDice() public returns (uint256) {
    lastRoll = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 6 + 1;
    return lastRoll;
}""",

"""mapping(address => uint256) public boostedReward;
function claimBoost(uint256 base) public {
    uint256 factor = gasleft() % 5 + 1;
    boostedReward[msg.sender] = base * factor;
}""",

"""uint256 public ticketCount;
mapping(uint256 => address) public ticketOwner;
function buyTicket() public {
    ticketOwner[ticketCount] = msg.sender;
    ticketCount += 1;
}
function pickRaffle() public view returns (address) {
    return ticketOwner[block.number % ticketCount];
}""",

"""address public prizeWinner;
function spinPrize() public {
    if (uint256(blockhash(block.number - 1)) % 7 == 0) {
        prizeWinner = msg.sender;
    }
}""",

"""uint8 public drawnCard;
function drawCard() public {
    drawnCard = uint8(uint256(blockhash(block.number - 1)) % 52);
}""",

"""uint256 public jackpotSeed;
function rollJackpot() public {
    jackpotSeed = uint256(keccak256(abi.encodePacked(address(this).balance, block.timestamp)));
}
function isJackpotHit() public view returns (bool) {
    return jackpotSeed % 1000 == 0;
}""",

"""mapping(address => bytes32) public sealedGuess;
function commitGuess(bytes32 commitment) public {
    sealedGuess[msg.sender] = commitment;
}
function revealOutcome() public view returns (bool) {
    return sealedGuess[msg.sender] == blockhash(block.number - 1);
}""",

"""uint256 public rngState = 12345;
function nextRandom() public returns (uint256) {
    rngState = (rngState * 1103515245 + 12345) % 2147483648;
    return rngState;
}""",

"""uint256 public mintedRarity;
function mintRare() public {
    mintedRarity = uint256(keccak256(abi.encodePacked(block.timestamp, block.number))) % 100;
}""",

"""uint256 public wheelSlot;
function spinWheel() public {
    wheelSlot = (block.timestamp / 15) % 12;
}""",

"""uint256 public gasSeed;
function seedFromGas() public {
    gasSeed = uint256(keccak256(abi.encodePacked(tx.gasprice, block.timestamp))) % 256;
}""",

"""mapping(address => uint256) public airdropAmount;
function claimRandomAirdrop() public {
    airdropAmount[msg.sender] = uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), msg.sender))) % 1000;
}""",

"""uint256 private hiddenNumber;
function setHidden() public {
    hiddenNumber = uint256(keccak256(abi.encodePacked(block.timestamp))) % 100;
}
function guessHidden(uint256 n) public view returns (bool) {
    return n == hiddenNumber;
}""",

"""uint256 public reelResult;
function pullLever() public {
    reelResult = uint256(keccak256(abi.encodePacked(block.timestamp, block.number, blockhash(block.number - 1), gasleft())));
}
function isReelWin() public view returns (bool) {
    return reelResult % 64 == 0;
}""",
]

# ---------------------------------------------------------------------------
# Front Running / TOD (0.8 dialect).
# Same archetypes as the 0.4 set; syntax updated for 0.8:
# - `string memory` / `bytes memory` params
# - `payable(msg.sender).transfer()` (msg.sender is non-payable address in 0.8)
# - `payable(highestBidder).transfer()` (address variables need explicit cast)
# ---------------------------------------------------------------------------
TOD = [
"""bytes32 constant rewardHash = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;
function submitAnswer(string memory answer) public {
    if (keccak256(abi.encodePacked(answer)) == rewardHash) {
        payable(msg.sender).transfer(address(this).balance);
    }
}""",

"""bool public bountyClaimed;
function claimBounty() public {
    require(!bountyClaimed);
    bountyClaimed = true;
    payable(msg.sender).transfer(address(this).balance);
}""",

"""uint256 public itemPrice;
mapping(address => uint256) public itemsOwned;
function setItemPrice(uint256 p) public {
    itemPrice = p;
}
function buyItem() public payable {
    require(msg.value >= itemPrice);
    itemsOwned[msg.sender] += 1;
}""",

"""uint256 public highestBid;
address public highestBidder;
function bid() public payable {
    require(msg.value > highestBid);
    if (highestBidder != address(0)) {
        payable(highestBidder).transfer(highestBid);
    }
    highestBid = msg.value;
    highestBidder = msg.sender;
}""",

"""mapping(address => mapping(address => uint256)) public allowed;
mapping(address => uint256) public tokenBalance;
function approveSpender(address spender, uint256 amount) public {
    allowed[msg.sender][spender] = amount;
}
function spendFrom(address from, uint256 amount) public {
    require(allowed[from][msg.sender] >= amount);
    allowed[from][msg.sender] -= amount;
    tokenBalance[msg.sender] += amount;
}""",

"""mapping(address => bool) public airdropTaken;
uint256 public airdropRemaining;
function grabAirdrop() public {
    require(airdropRemaining > 0);
    require(!airdropTaken[msg.sender]);
    airdropTaken[msg.sender] = true;
    airdropRemaining -= 1;
    payable(msg.sender).transfer(1 ether);
}""",

"""uint256 public mintsLeft;
uint256 public mintPrice;
function mintToken() public payable {
    require(mintsLeft > 0);
    require(msg.value >= mintPrice);
    mintsLeft -= 1;
}""",

"""uint256 public puzzleReward;
bool public puzzleSolved;
function solvePuzzle(uint256 solution) public {
    require(!puzzleSolved);
    require(solution * solution == 144);
    puzzleSolved = true;
    payable(msg.sender).transfer(puzzleReward);
}""",

"""mapping(address => uint256) public collateral;
mapping(address => uint256) public debt;
function liquidate(address user) public {
    require(debt[user] > collateral[user]);
    uint256 bonus = collateral[user];
    collateral[user] = 0;
    debt[user] = 0;
    payable(msg.sender).transfer(bonus);
}""",

"""mapping(bytes32 => bool) public codeUsed;
function redeemCode(string memory code) public {
    bytes32 h = keccak256(abi.encodePacked(code));
    require(!codeUsed[h]);
    codeUsed[h] = true;
    payable(msg.sender).transfer(0.1 ether);
}""",

"""mapping(bytes32 => address) public nameOwner;
function registerName(string memory name) public {
    bytes32 h = keccak256(abi.encodePacked(name));
    require(nameOwner[h] == address(0));
    nameOwner[h] = msg.sender;
}""",

"""uint256 public reserveA;
uint256 public reserveB;
function swapAForB(uint256 amountA) public returns (uint256) {
    uint256 out = reserveB * amountA / (reserveA + amountA);
    reserveA += amountA;
    reserveB -= out;
    return out;
}""",

"""uint256 public oraclePrice;
mapping(address => uint256) public bought;
function updateOraclePrice(uint256 p) public {
    oraclePrice = p;
}
function buyAtOracle(uint256 qty) public payable {
    require(msg.value >= qty * oraclePrice);
    bought[msg.sender] += qty;
}""",

"""bytes32 public secretCommit;
uint256 public revealReward;
function setCommit(bytes32 c) public {
    secretCommit = c;
}
function revealSecret(string memory secret) public {
    require(keccak256(abi.encodePacked(secret)) == secretCommit);
    payable(msg.sender).transfer(revealReward);
}""",

"""uint256 public counter;
address public champion;
function increment() public {
    counter += 1;
    if (counter == 100) {
        champion = msg.sender;
        payable(msg.sender).transfer(address(this).balance);
    }
}""",

"""bool public payoutOpen;
uint256 public payoutPool;
function openPayout() public {
    payoutOpen = true;
}
function withdrawPayout() public {
    require(payoutOpen);
    uint256 amount = payoutPool;
    payoutPool = 0;
    payable(msg.sender).transfer(amount);
}""",
]


def clear_tf(out_dir):
    if os.path.isdir(out_dir):
        for f in os.listdir(out_dir):
            if f.endswith(".txt"):
                os.remove(os.path.join(out_dir, f))


def write_set(name, fragments):
    out_dir = os.path.join(BUGS, name, "v08", "tf")
    os.makedirs(out_dir, exist_ok=True)
    clear_tf(out_dir)
    for i, frag in enumerate(fragments, 1):
        with open(os.path.join(out_dir, f"{i}.txt"), "w", newline="\n") as f:
            f.write(frag.strip() + "\n")
    print(f"wrote {len(fragments)} distinct snippets -> bugs/{name}/v08/tf/")


def main():
    write_set("DoS", DOS)
    write_set("Bad-Randomness", BAD_RANDOMNESS)
    write_set("TOD", TOD)


if __name__ == "__main__":
    main()

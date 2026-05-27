"""Generate DIVERSE solc-0.4-compatible tf-snippets for TOD (Front Running), DoS, Bad-Randomness.

0.4 has no `address payable` (plain `address` is payable), `.pop()` (use `.length--`), and
`.call(data)` returns a single bool (not a tuple). Compiled with solc 0.4.26, so
abi.encodePacked / blockhash() / keccak256 / require are available. Written to
bugs/<Type>/v04/tf/ ; the family-aware injector prefers these for 0.4.x bases.

The 0.4.x family is the bulk of the injectable corpus, so its snippets MUST be diverse:
each fragment is a different archetype with its own natural vocabulary (no `TOD`/`BR`/`DoS`/`v04`
identifier token), giving cross-file-unique identifiers and no synthetic fingerprint for a
frozen encoder to memorize. No self-labeling comments (forbidden by the rulebook).
"""
import os

SOLIDIFI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "SolidiFI")
BUGS = os.path.join(SOLIDIFI, "bugs")

# ---------------------------------------------------------------------------
# Front Running / TOD — outcome depends on transaction ordering; a watcher can
# front-run the victim's tx. Distinct flows: race-to-claim, guess-reveal,
# anchored price, auction snipe, approve race, first-come claim/mint/register,
# liquidation bonus, slippage-free swap, oracle front-run.
# ---------------------------------------------------------------------------
TOD = [
"""bytes32 constant rewardHash = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;
function submitAnswer(string answer) public {
    if (keccak256(abi.encodePacked(answer)) == rewardHash) {
        msg.sender.transfer(address(this).balance);
    }
}""",

"""bool public bountyClaimed;
function claimBounty() public {
    require(!bountyClaimed);
    bountyClaimed = true;
    msg.sender.transfer(address(this).balance);
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
        highestBidder.transfer(highestBid);
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
    msg.sender.transfer(1 ether);
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
    msg.sender.transfer(puzzleReward);
}""",

"""mapping(address => uint256) public collateral;
mapping(address => uint256) public debt;
function liquidate(address user) public {
    require(debt[user] > collateral[user]);
    uint256 bonus = collateral[user];
    collateral[user] = 0;
    debt[user] = 0;
    msg.sender.transfer(bonus);
}""",

"""mapping(bytes32 => bool) public codeUsed;
function redeemCode(string code) public {
    bytes32 h = keccak256(abi.encodePacked(code));
    require(!codeUsed[h]);
    codeUsed[h] = true;
    msg.sender.transfer(0.1 ether);
}""",

"""mapping(bytes32 => address) public nameOwner;
function registerName(string name) public {
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
function revealSecret(string secret) public {
    require(keccak256(abi.encodePacked(secret)) == secretCommit);
    msg.sender.transfer(revealReward);
}""",

"""uint256 public counter;
address public champion;
function increment() public {
    counter += 1;
    if (counter == 100) {
        champion = msg.sender;
        msg.sender.transfer(address(this).balance);
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
    msg.sender.transfer(amount);
}""",
]

# ---------------------------------------------------------------------------
# DoS (0.4 dialect) — unbounded operations / failed-call-blocks-everyone.
# ---------------------------------------------------------------------------
DOS = [
"""address[] public shareholders;
mapping(address => uint256) public dividend;
function addShareholder(address who, uint256 amount) public {
    shareholders.push(who);
    dividend[who] = amount;
}
function payDividends() public {
    for (uint256 i = 0; i < shareholders.length; i++) {
        shareholders[i].transfer(dividend[shareholders[i]]);
    }
}""",

"""address[] public refundList;
mapping(address => uint256) public owed;
function queueRefund(address who, uint256 amount) public {
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
function notifyAll(bytes payload) public {
    for (uint256 i = 0; i < subscribers.length; i++) {
        bool ok = subscribers[i].call(payload);
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

"""struct Withdrawal { address to; uint256 amount; }
Withdrawal[] public withdrawalQueue;
function enqueueWithdrawal(address to, uint256 amount) public {
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

"""address[] public bidders;
mapping(address => uint256) public bidAmount;
function placeAuctionBid() public payable {
    bidders.push(msg.sender);
    bidAmount[msg.sender] += msg.value;
}
function closeAuction() public {
    for (uint256 i = 0; i < bidders.length; i++) {
        bidders[i].transfer(bidAmount[bidders[i]]);
    }
}""",

"""address[] public airdropList;
function enrollAirdrop(address who) public {
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
    registry.length--;
}""",

"""address[] public payees;
function addPayee(address who) public {
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
        require(members[i].call.value(1)());
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
# Bad Randomness (0.4 dialect).
# ---------------------------------------------------------------------------
BR = [
"""address[] public lotteryPlayers;
uint256 public lotteryPot;
function joinLottery() public payable {
    lotteryPlayers.push(msg.sender);
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
        msg.sender.transfer(coinflipStake[msg.sender] * 2);
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
    if (uint256(block.difficulty) % 7 == 0) {
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


def clear_tf(out_dir):
    if os.path.isdir(out_dir):
        for f in os.listdir(out_dir):
            if f.endswith(".txt"):
                os.remove(os.path.join(out_dir, f))


def write_set(name, fragments):
    out_dir = os.path.join(BUGS, name, "v04", "tf")
    os.makedirs(out_dir, exist_ok=True)
    clear_tf(out_dir)
    for i, frag in enumerate(fragments, 1):
        with open(os.path.join(out_dir, f"{i}.txt"), "w", newline="\n") as f:
            f.write(frag.strip() + "\n")
    print(f"wrote {len(fragments)} distinct snippets -> bugs/{name}/v04/tf/")


def main():
    write_set("TOD", TOD)
    write_set("DoS", DOS)
    write_set("Bad-Randomness", BR)


if __name__ == "__main__":
    main()

"""Generate DIVERSE custom SolidiFI tf-snippets for DoS and Bad-Randomness (solc-0.5 family).

Each class gets a LIBRARY of structurally-distinct, realistic contract-body fragments
(state vars + functions) inserted at function/block boundaries. solc-0.5.12+ compatible.

Why diverse (not one cloned template): SolidiFI injects a *sequence* of these files into
each base (one per injection point), and the same files are reused across ~1,300 bases. A
single repeated template + class-named identifiers (`_BR`, `_DoS`) becomes a lexical/structural
shortcut a frozen encoder memorizes instead of learning the vulnerability concept — high train
F1, poor transfer to the real test. Each fragment here is a different archetype with its OWN
natural vocabulary (no `BR`/`DoS`/`v0x` token), so identifiers are unique across files (required:
multiple fragments co-exist in one injected contract) and carry no synthetic fingerprint.
No self-labeling comments (forbidden by the rulebook).
"""
import os

SOLIDIFI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "SolidiFI")
BUGS = os.path.join(SOLIDIFI, "bugs")

# ---------------------------------------------------------------------------
# Bad Randomness — entropy derived from miner/predictable on-chain values.
# Distinct entropy sources & flows: blockhash, timestamp, number, difficulty,
# gasleft, gasprice, contract balance, public-state LCG, leaky commit-reveal.
# ---------------------------------------------------------------------------
BAD_RANDOMNESS = [
"""address payable[] public lotteryPlayers;
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

# ---------------------------------------------------------------------------
# DoS — unbounded operations / failed-call-blocks-everyone (gas griefing).
# Distinct mechanisms: push-payment loops, external call in loop, unbounded
# growth + iterate, O(n) insert, array-shift removal, batch with single require.
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
    bidders.push(msg.sender);
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
        (bool ok, ) = members[i].call.value(1)("");
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


def clear_tf(out_dir):
    if os.path.isdir(out_dir):
        for f in os.listdir(out_dir):
            if f.endswith(".txt"):
                os.remove(os.path.join(out_dir, f))


def write_set(name, fragments):
    out_dir = os.path.join(BUGS, name, "tf")
    os.makedirs(out_dir, exist_ok=True)
    clear_tf(out_dir)
    for i, frag in enumerate(fragments, 1):
        with open(os.path.join(out_dir, f"{i}.txt"), "w", newline="\n") as f:
            f.write(frag.strip() + "\n")
    print(f"wrote {len(fragments)} distinct snippets -> bugs/{name}/tf/")


def main():
    write_set("DoS", DOS)
    write_set("Bad-Randomness", BAD_RANDOMNESS)

    conf = os.path.join(SOLIDIFI, "bug_types.conf")
    with open(conf) as f:
        text = f.read()
    additions = ""
    if "bug_type=DoS" not in text:
        additions += "\n[8]\nbug_type_id=8\nbug_type=DoS\nbug_type_dir=DoS\n"
    if "bug_type=Bad-Randomness" not in text:
        additions += "\n[9]\nbug_type_id=9\nbug_type=Bad-Randomness\nbug_type_dir=Bad-Randomness\n"
    if additions:
        with open(conf, "a") as f:
            f.write(additions)
        print("appended bug_types.conf entries:", additions.strip().replace("\n", " "))
    else:
        print("bug_types.conf already has DoS/Bad-Randomness")


if __name__ == "__main__":
    main()

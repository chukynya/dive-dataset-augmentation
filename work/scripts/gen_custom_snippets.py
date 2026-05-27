"""Generate custom SolidiFI tf-snippets for DoS and Bad-Randomness.

Mirrors the existing bugs/<type>/tf/ layout: each file is a self-contained
contract-body fragment (state vars + functions) inserted at function/block
boundaries. Written in solc-0.5.12-compatible Solidity, with unique numeric
identifier suffixes so multiple snippets can co-exist in one contract without
name collisions. No self-labeling comments (forbidden by the rulebook).
"""
import os

SOLIDIFI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "SolidiFI")
BUGS = os.path.join(SOLIDIFI, "bugs")
N = 12  # variants per type

# DoS: unbounded loop over a dynamic array performing an external transfer
# (gas-griefing / unbounded-operation DoS). A single failing/expensive entry
# blocks payouts for everyone.
DOS = """address payable[] private participants_DoS{i};
mapping(address => uint256) private balances_DoS{i};

function enroll_DoS{i}(address payable account, uint256 amount) public {{
    participants_DoS{i}.push(account);
    balances_DoS{i}[account] += amount;
}}

function distribute_DoS{i}() public {{
    for (uint256 idx = 0; idx < participants_DoS{i}.length; idx++) {{
        address payable account = participants_DoS{i}[idx];
        account.transfer(balances_DoS{i}[account]);
        balances_DoS{i}[account] = 0;
    }}
}}"""

# Bad-Randomness: derives "randomness" from block variables (timestamp, number,
# blockhash) which are miner-influenceable and predictable.
BR = """uint256 private seed_BR{i};
address private winner_BR{i};

function draw_BR{i}(uint256 stake) public returns (bool) {{
    uint256 entropy = uint256(keccak256(abi.encodePacked(block.timestamp, block.number, blockhash(block.number - 1), stake)));
    seed_BR{i} = entropy;
    if (entropy % 2 == 0) {{
        winner_BR{i} = msg.sender;
        return true;
    }}
    return false;
}}

function lastWinner_BR{i}() public view returns (address) {{
    return winner_BR{i};
}}"""


def write_set(name, template):
    d = os.path.join(BUGS, name, "tf")
    os.makedirs(d, exist_ok=True)
    for i in range(1, N + 1):
        with open(os.path.join(d, f"{i}.txt"), "w", newline="\n") as f:
            f.write(template.format(i=i) + "\n")
    print(f"wrote {N} snippets -> bugs/{name}/tf/")


def main():
    write_set("DoS", DOS)
    write_set("Bad-Randomness", BR)

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

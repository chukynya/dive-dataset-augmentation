"""Generate solc-0.4-compatible tf-snippets for the 5 built-in SolidiFI types
used by the majority classes. Upstream 0.5-style snippets serve 0.5/0.6/0.7;
these v04 variants serve 0.4.x bases. No self-labeling comments.
"""
import os

SOLIDIFI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "SolidiFI")
BUGS = os.path.join(SOLIDIFI, "bugs")
N = 12

# dir name in bug_types.conf -> snippet template (0.4-compatible)
SETS = {
    # Reentrancy: external call before the balance update.
    "Re-entrancy": """mapping(address => uint256) balances_RE_v04_{i};

function deposit_RE_v04_{i}() public payable {{
    balances_RE_v04_{i}[msg.sender] += msg.value;
}}

function withdraw_RE_v04_{i}(uint256 amount) public {{
    require(balances_RE_v04_{i}[msg.sender] >= amount);
    if (msg.sender.call.value(amount)()) {{
        balances_RE_v04_{i}[msg.sender] -= amount;
    }}
}}""",
    # Access Control via tx.origin auth.
    "tx-origin": """address owner_AC_v04_{i};

function claimOwner_AC_v04_{i}() public {{
    owner_AC_v04_{i} = msg.sender;
}}

function setOwner_AC_v04_{i}(address newOwner) public {{
    require(tx.origin == owner_AC_v04_{i});
    owner_AC_v04_{i} = newOwner;
}}""",
    # Arithmetic overflow/underflow (no SafeMath, 0.4 has no built-in checks).
    "Overflow-Underflow": """mapping(address => uint256) bal_OF_v04_{i};

function credit_OF_v04_{i}(uint256 value) public {{
    bal_OF_v04_{i}[msg.sender] += value;
}}

function move_OF_v04_{i}(address to, uint256 value) public {{
    bal_OF_v04_{i}[msg.sender] -= value;
    bal_OF_v04_{i}[to] += value;
}}""",
    # Unchecked send return value.
    "Unchecked-Send": """function payout_US_v04_{i}(address recipient, uint256 amount) public {{
    recipient.send(amount);
}}""",
    # Timestamp dependency.
    "Timestamp-Dependency": """address winner_TS_v04_{i};
uint256 last_TS_v04_{i};

function play_TS_v04_{i}() public payable {{
    last_TS_v04_{i} = now;
    if (now % 15 == 0) {{
        winner_TS_v04_{i} = msg.sender;
    }}
}}""",
}


def main():
    for d, tmpl in SETS.items():
        out = os.path.join(BUGS, d, "v04", "tf")
        os.makedirs(out, exist_ok=True)
        for i in range(1, N + 1):
            with open(os.path.join(out, f"{i}.txt"), "w", newline="\n") as f:
                f.write(tmpl.format(i=i) + "\n")
        print(f"wrote {N} -> bugs/{d}/v04/tf/")


if __name__ == "__main__":
    main()

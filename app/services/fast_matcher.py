"""High-Performance Aho-Corasick Multi-Pattern Automaton for vGuard DPI.

Matches hundreds of detection signatures in a single linear pass O(N) over packet
payloads, replacing slow O(M * N) nested loop searches.
"""
from collections import deque
from typing import Dict, List, Optional, Set, Tuple


class AhoCorasickNode:
    __slots__ = ("children", "fail", "outputs")

    def __init__(self):
        self.children: Dict[str, "AhoCorasickNode"] = {}
        self.fail: Optional["AhoCorasickNode"] = None
        # List of tuples: (attack_type, signature_string)
        self.outputs: List[Tuple[str, str]] = []


class FastPatternMatcher:
    """Deterministic Finite Automaton (DFA) for O(N) multi-signature DPI scanning."""

    def __init__(self, rules_dict: Optional[Dict[str, List[str]]] = None):
        self.root = AhoCorasickNode()
        self.pattern_count = 0
        self.category_count = 0
        if rules_dict:
            self.build(rules_dict)

    def build(self, rules_dict: Dict[str, List[str]]) -> None:
        """Build the Trie and compute failure transitions via BFS."""
        self.root = AhoCorasickNode()
        self.pattern_count = 0
        self.category_count = len(rules_dict)

        # 1. Insert all patterns into Trie
        for category, signatures in rules_dict.items():
            cat_upper = str(category).upper()
            for sig in signatures:
                sig_lower = str(sig).lower().strip()
                if not sig_lower:
                    continue

                curr = self.root
                for ch in sig_lower:
                    if ch not in curr.children:
                        curr.children[ch] = AhoCorasickNode()
                    curr = curr.children[ch]

                curr.outputs.append((cat_upper, str(sig)))
                self.pattern_count += 1

        # 2. Build BFS failure transitions
        queue = deque()
        for ch, child in self.root.children.items():
            child.fail = self.root
            queue.append(child)

        while queue:
            curr = queue.popleft()

            for ch, child in curr.children.items():
                fail_node = curr.fail
                while fail_node is not None and ch not in fail_node.children:
                    fail_node = fail_node.fail

                child.fail = fail_node.children[ch] if fail_node else self.root
                # Inherit outputs from fail link
                if child.fail and child.fail.outputs:
                    child.outputs.extend(child.fail.outputs)

                queue.append(child)

    def search_first(self, text: str) -> Tuple[Optional[str], Optional[str]]:
        """Search text in a single pass. Return (category, signature) of first match."""
        if not text:
            return None, None

        curr = self.root
        for ch in text.lower():
            while curr is not None and ch not in curr.children:
                curr = curr.fail

            if curr is None:
                curr = self.root
                continue

            curr = curr.children[ch]
            if curr.outputs:
                # Return the highest priority or first matched signature
                return curr.outputs[0]

        return None, None

    def search_all(self, text: str) -> List[Tuple[str, str]]:
        """Search text in a single pass. Return all matching (category, signature) pairs."""
        if not text:
            return []

        results = []
        seen = set()
        curr = self.root

        for ch in text.lower():
            while curr is not None and ch not in curr.children:
                curr = curr.fail

            if curr is None:
                curr = self.root
                continue

            curr = curr.children[ch]
            if curr.outputs:
                for match in curr.outputs:
                    if match not in seen:
                        seen.add(match)
                        results.append(match)

        return results


# Global singleton instance for high-throughput packet processing
_fast_matcher_instance: Optional[FastPatternMatcher] = None


def get_fast_matcher(rules_dict: Optional[Dict[str, List[str]]] = None) -> FastPatternMatcher:
    """Return the global fast matcher singleton, initializing if necessary."""
    global _fast_matcher_instance
    if _fast_matcher_instance is None or rules_dict is not None:
        if rules_dict is None:
            from rule_manager import load_rules
            rules_dict = load_rules()
        _fast_matcher_instance = FastPatternMatcher(rules_dict)
    return _fast_matcher_instance

from typing import List, Tuple, Dict

def hamming_distance(h1: str, h2: str) -> int:
    b1 = bin(int(h1, 16))[2:].zfill(64)
    b2 = bin(int(h2, 16))[2:].zfill(64)
    return sum(c1 != c2 for c1, c2 in zip(b1, b2))

class CERFClusterer:
    def cluster_sessions(self, session_cerfs: List[Tuple[str, str]], threshold: int = 4) -> Dict[str, str]:
        """Clusters session IDs into Threat Actor IDs based on CERF hash Hamming distance <= 4."""
        clusters = {}
        ta_counter = 1
        session_to_ta = {}
        
        for session_id, cerf in session_cerfs:
            assigned = False
            for c_id, c_cerf in clusters.items():
                if hamming_distance(cerf, c_cerf) <= threshold:
                    session_to_ta[session_id] = c_id
                    assigned = True
                    break
            if not assigned:
                new_ta_id = f"TA-{ta_counter:03d}"
                clusters[new_ta_id] = cerf
                session_to_ta[session_id] = new_ta_id
                ta_counter += 1
                
        return session_to_ta

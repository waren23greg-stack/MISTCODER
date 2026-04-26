from __future__ import annotations

FPIC_REQUIRED = {"Mau Forest", "Ogiek Territory", "Sengwer Homeland"}
PROTECTED     = {"Mau Forest": "Kenya Forest Reserve", "Aberdare": "National Park",
                 "Maasai Mara": "National Reserve", "Tsavo": "National Park"}
BIO_THRESHOLD = 4.0
ECO_CONF_MIN  = 0.60


class Lex0Engine:
    def review(self, event_id, steps, bio_score, eco_confidence,
               region="Unknown", fpic_cleared=True):
        if bio_score < BIO_THRESHOLD:
            return False, f"BioImpact {bio_score} below threshold {BIO_THRESHOLD} — likely noise"
        if eco_confidence < ECO_CONF_MIN:
            return False, f"EcoOracle confidence {eco_confidence} insufficient"
        if region in FPIC_REQUIRED and not fpic_cleared:
            return False, f"FPIC not cleared for {region}"
        eco_codes = [s for s in steps if s.startswith("ECO-")]
        if not eco_codes:
            return False, "No ECO impact code in steps"
        zone = PROTECTED.get(region, "monitored zone")
        return True, (f"Score {bio_score} meets threshold. "
                      f"EcoBrain {eco_confidence:.3f}. {region} ({zone}) certified.")

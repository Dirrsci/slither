"""
    Check that pragma directives dont' use the floating syntax
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FloatingPragma(AbstractDetector):
    """
    Check that pragma directives dont' use the floating syntax
    """

    ARGUMENT = 'floating-pragma'
    HELP = 'If using floating pragma directive'
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = 'https://cwe.mitre.org/data/definitions/664.html'

    def detect(self):
        results = []
        pragma = self.slither.pragma_directives
        versions = [p.version for p in pragma]
        versions = sorted(list(set(versions)))

        if any("^" in v for v in versions):
            info = "Floating pragma used in {}:\n".format(self.filename)
            self.log(info)
            json = self.generate_json_result(info)
            # follow the same format than add_nodes_to_json
            json['expressions'] = [{'expression': p.version,
                                    'source_mapping': p.source_mapping} for p in pragma]
            results.append(json)

        return results

"""Experimental F2 features without the leading www. hostname prefix."""

from src.features.f2_ngram import F2Vectorizer


class F2VectorizerNoWWW(F2Vectorizer):
    def _parts(self, urls):
        hosts, paths = super()._parts(urls)

        normalized_hosts = [
            host[4:] if host.startswith("www.") else host
            for host in hosts
        ]

        return normalized_hosts, paths

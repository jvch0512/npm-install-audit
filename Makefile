test:
	node --test tests/*.test.js

sample:
	mkdir -p docs site
	bin/npm-install-audit examples > docs/sample-output.txt; true
	bin/npm-install-audit examples --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "npm-install-audit" "Audits package.json and package-lock.json for dangerous install scripts, git and URL dependencies, wildcard versions and plain-HTTP tarballs. Zero dependencies, Node." "Synthetic manifests."

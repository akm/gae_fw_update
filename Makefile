GITHUB_ORG  = akm
GITHUB_REPO = gae_fw_update

BASEDIR = $(CURDIR)
PKGDIR_NAME  = pkg
PKGDIR  = $(CURDIR)/$(PKGDIR_NAME)
VERSION ?= `grep Version version.go | cut -f2 -d\"`

.PHONY: setup
setup:
	@which dep || go get -u github.com/golang/dep/cmd/dep
	@which gox || github.com/mitchellh/gox
	@which ghr || github.com/tcnksm/ghr

.PHONY: init
init: setup Gopkg.toml .gitignore

Gopkg.toml:
	@dep init
.gitignore:
	@echo "/vendor" >> .gitignore
	@echo "/${PKGDIR_NAME}" >> .gitignore

.PHONY: dep_ensure
dep_ensure:
	@dep ensure

.PHONY: build
build:
	go build .

.PHONY: version
version:
	@echo ${VERSION}

.PHONY: git_tag git_push_tag tag
git_tag:
	git tag v${VERSION}
git_push_tag:
	git push origin v${VERSION}
tag: git_tag git_push_tag

.PHONY: packages
packages: OS_LIST := linux darwin
packages: ARCH := amd64
packages: PARALLEL := 2
packages:
	gox -output="${PKGDIR}/{{.Dir}}_{{.OS}}_{{.Arch}}" -os="${OS_LIST}" -arch="${ARCH}" -parallel=${PARALLEL}

.PHONY: prerelease release
release:
	ghr -u $(GITHUB_ORG) -r $(GITHUB_REPO) --replace --draft ${VERSION} pkg
prerelease:
	ghr -u $(GITHUB_ORG) -r $(GITHUB_REPO) --replace --draft --prerelease ${VERSION} pkg

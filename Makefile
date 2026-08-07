# jun-bank/infra — 빌드 및 검사 타깃.
# 강제 가능한 게이트는 `build`와 `vet`이다(stdlib 전용, 항상 사용 가능).
# `lint`는 golangci-lint가 필요하고; `test`는 (현재 골격인) 테스트 스위트를 실행한다.

.PHONY: build test test-integration lint vet all

# all은 머지 게이트에 해당하는 검사를 순서대로 실행한다(ADR/test-strategy: compile과
# vet이 가장 저렴한 게이트이며; lint와 test가 그 위에 위치한다).
all: build vet test

# build는 모든 command와 package를 컴파일한다. 이것이 주 게이트다: 모든 커밋은
# `go build ./...`를 green으로 유지해야 한다.
build:
	go build ./...

# vet은 컴파일러가 허용하는 의심스러운 구성을 잡아낸다. 모든 커밋의 일부다.
vet:
	go vet ./...

# test는 유닛 테스트를 실행한다(기본 빌드 태그 — 통합 테스트 제외).
test:
	go test ./...

# test-integration은 배포 스키마 계약을 실제 MySQL에 대해 검증한다(Testcontainers —
# Docker 필요). `integration` 태그로만 컴파일되므로 기본 test 게이트와 분리된다
# (internal/store/store_integration_test.go 참조).
test-integration:
	go test -tags integration ./...

# lint는 .golangci.yml에 대해 golangci-lint를 실행한다. PATH에 golangci-lint가
# 필요하며; 벤더링되지 않았으므로 도구가 준비되기 전까지 이 타깃은 참고용이다.
lint:
	golangci-lint run

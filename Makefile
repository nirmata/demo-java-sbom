.DEFAULT_GOAL: build


build:
	@echo "Building..."
	docker build . -t ghcr.io/nirmata/demo-java-sbom:azul11 -f azul11/Dockerfile
	docker build . -t ghcr.io/nirmata/demo-java-sbom:correto17 -f correto17/Dockerfile
	docker build . -t ghcr.io/nirmata/demo-java-sbom:openjdk11 -f openjdk11/Dockerfile
	docker build . -t ghcr.io/nirmata/demo-java-sbom:ubuntujre7 -f ubuntujre7/Dockerfile

push:
	@echo "Pushing images..."
	docker push ghcr.io/nirmata/demo-java-sbom:azul11 
	docker push ghcr.io/nirmata/demo-java-sbom:correto17 
	docker push ghcr.io/nirmata/demo-java-sbom:openjdk11 
	docker push ghcr.io/nirmata/demo-java-sbom:ubuntujre7

sbom:
	@echo "Generating SBOMs..."
	syft -o syft-json ghcr.io/nirmata/demo-java-sbom:azul11 | jq > sboms/azul11.json
	syft -o syft-json ghcr.io/nirmata/demo-java-sbom:correto17 | jq  > sboms/correto17.json
	syft -o syft-json ghcr.io/nirmata/demo-java-sbom:openjdk11 | jq > sboms/openjdk11.json
	syft -o syft-json ghcr.io/nirmata/demo-java-sbom:ubuntujre7 | jq > sboms/ubuntujre7.json

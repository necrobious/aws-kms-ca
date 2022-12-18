TARGET = aarch64-unknown-linux-gnu
#TARGET = aarch64-unknown-linux-musl

.PHONY: deploy clean build synth

cargo_build:
	cargo lambda build --release --output-format zip --target $(TARGET)

delete_zip:
	find target -name bootstrap.zip -exec rm -fv {} \;

remove_cdk_out:
	rm -rf cdk.out

cargo_clean:
	cargo clean

cdk_synth:
	(LAMBDA_ZIP_FILE_PATH=`find target -name bootstrap.zip` cdk synth)

cdk_deploy:
	(LAMBDA_ZIP_FILE_PATH=`find target -name bootstrap.zip` cdk deploy)


deploy: cargo_build cdk_deploy
synth: cargo_build cdk_synth
build: delete_zip cargo_build 
clean: cargo_clean remove_cdk_out

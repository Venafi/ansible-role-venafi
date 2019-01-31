pep8:
	pycodestyle --first ./library/venafi_certificate.py

lint:
	ansible-lint ./tasks/*
	ansible-lint ./meta/*
	ansible-lint ./defaults/*

ansible-molecule-check:
	ANSIBLE_VAULT_PASSWORD_FILE=${PWD}/vault-password.txt molecule check

ansible-molecule-verify:
	ANSIBLE_VAULT_PASSWORD_FILE=${PWD}/vault-password.txt molecule verify

#Testing ansible crypto modules for examples and compability checks
test-crypto-playbook:
	ansible-playbook -i tests/inventory tests/crypto.yml

#test ansible role with venafi_Certificate module
test-vcert-role-tpp:
#	#have to copy library to test our module, otherwise test playbook will not
	docker build ./tests --tag local-ansible-test
	rm -rvf tests/library
	cp -rv library tests/
	ansible-playbook -i tests/inventory tests/venafi-playbook-example.yml \
	--vault-password-file vault-password.txt \
	--extra-vars "credentials_file=tpp_credentials.yml docker_demo=true"

test-vcert-role-cloud:
#	#have to copy library to test our module, otherwise test playbook will not
	docker build ./tests --tag local-ansible-test
	rm -rvf tests/library
	cp -rv library tests/
	ansible-playbook -i tests/inventory tests/venafi-playbook-example.yml \
	--vault-password-file vault-password.txt \
	--extra-vars "credentials_file=cloud_credentials.yml docker_demo=true"

test-vcert-role-fake:
#	#have to copy library to test our module, otherwise test playbook will not
	docker build ./tests --tag local-ansible-test
	rm -rvf tests/library
	cp -rv library tests/
	ansible-playbook -i tests/inventory tests/venafi-playbook-example.yml \
	--vault-password-file vault-password.txt \
	--extra-vars "credentials_file=fake_credentials.yml docker_demo=true"

#test module with python using json for args
test-python-module: test-python-module-fake test-python-module-tpp test-python-module-cloud

test-python-module-tpp:
	python3 library/venafi_certificate.py venafi_certificate_tpp.json

test-python-module-fake:
	python3 ./library/venafi_certificate.py venafi_certificate_fake.json

test-python-module-cloud:
	python3 ./library/venafi_certificate.py venafi_certificate_cloud.json

unit-test:
	rm -rvf tests/library
	cp -rv library tests/
	PYTHONPATH=./:$PYTHONPATH pytest tests/test_venafi_certificate.py

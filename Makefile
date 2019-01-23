pep8:
	pycodestyle --first ./library/venafi_certificate.py

lint:
	ansible-lint ./tasks/*
	ansible-lint ./meta/*
	ansible-lint ./defaults/*

#Testing ansible crypto modules for examples and compability checks
test-crypto-playbook:
	ansible-playbook -i tests/inventory tests/crypto.yml

#test ansible role with venafi_Certificate module
test-vcert-role:
#	#have to copy library to test our module, otherwise test playbook will not
	rm -rv tests/library
	cp -rv library tests/
	ansible-playbook -i tests/inventory tests/test.yml

#test module with python using json for args
test-python-module: test-python-module-fake test-python-module-tpp test-python-module-cloud

test-python-module-tpp:
	python3 library/venafi_certificate.py venafi_certificate_tpp.json

test-python-module-fake:
	python3 ./library/venafi_certificate.py venafi_certificate_fake.json

test-python-module-cloud:
	python3 ./library/venafi_certificate.py venafi_certificate_cloud.json
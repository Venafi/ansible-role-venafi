pep8:
	pycodestyle --first ./library/venafi_certificate.py

lint:
	ansible-lint ./tasks/*
	ansible-lint ./meta/*
	ansible-lint ./defaults/*

#Testing ansible crypto modules for examples and compability checks
ansible-test-crypto:
	ansible-playbook -i test-inventory-crypto test-crypto.yaml

python-tpp-test:
	python3 library/venafi_certificate.py venafi_certificate_tpp.json

python-fake-test:
	python3 ./library/venafi_certificate.py venafi_certificate_fake.json

python-cloud-test:
	python3 ./library/venafi_certificate.py venafi_certificate_cloud.json
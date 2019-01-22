pep8:
	pycodestyle --first ./library/venafi_certificate.py

ansible-test:
	ansible-playbook -i test-inventory test.yaml

python-tpp-test:
	python3 library/venafi_certificate.py venafi_certificate_tpp.json

python-fake-test:
	python3 ./library/venafi_certificate.py venafi_certificate_fake.json

python-cloud-test:
	python3 ./library/venafi_certificate.py venafi_certificate_cloud.json
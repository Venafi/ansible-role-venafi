pep8:
	pycodestyle --first ./library/venafi_certificate.py

test:
	ansible-playbook ./test_module_venafi_certificate.yml
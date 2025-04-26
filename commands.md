## Internal use:

pip install pyscard==2.2.1

python -m build
pip install .\dist\thalessecuritykey-0.0.9-py3-none-any.whl --force-reinstall

py -m  twine upload -r testpypi dist/*
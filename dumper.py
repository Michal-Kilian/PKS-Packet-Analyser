# Michal Kilian - ID: 116211 - PKS - zadanie 1
# module that contains help function in regard to dumping the final dictionary to a yaml output file
from ruamel.yaml import YAML


# function that dumps the final dictionary to a yaml output file
def yaml_dump(dictionary, output_file):
    with open(output_file, 'w') as file:
        yaml = YAML()
        yaml.representer.ignore_aliases = lambda x: True
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.dump(dictionary, file)

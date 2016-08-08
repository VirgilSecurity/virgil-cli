import subprocess
import re


class UtilHelp:
    def __init__(self, name, synopsis, options, examples):
        self.name = name
        self.synopsis = synopsis
        self.options = options
        self.examples = examples


def call_terminal(args):
    rd = subprocess.check_output(args)
    return rd.decode("utf-8")


def get_help(args):
    util_help = call_terminal(args)

    # NAME - short description
    pattern_name = re.compile(u'DESCRIPTION:(.*?)EXAMPLES', re.DOTALL)
    match_name = re.search(pattern_name, util_help)
    name = match_name.group(1).strip() + "\n"

    # SYNOPSIS
    pattern_synopsis = re.compile(u'Synopsis:(.*?)Options', re.DOTALL)
    match_synopsis = re.search(pattern_synopsis, util_help)
    synopsis = "   " + match_synopsis.group(1).strip() + "\n"

    # OPTIONS
    pattern_options = re.compile(u'Options:(.*?)DESCRIPTION', re.DOTALL)
    match_options = re.search(pattern_options, util_help)
    options = "    " + match_options.group(1).strip() + "\n"

    # EXAMPLES
    pattern_examples = re.compile(u'EXAMPLES:(.*?)\Z', re.DOTALL)
    match_examples = re.search(pattern_examples, util_help)
    examples = "  " + match_examples.group(1).strip() + "\n"
    return UtilHelp(name, synopsis, options, examples.replace('\t', '  '))


def underline(str):
    return "*" * len(str)


def separator(str):
    return "=" * len(str)


def create_man_page(util_name, util_help = UtilHelp("", "", "", "")):
    index_name_doc = underline(util_name) + "\n" + util_name + "\n" + underline(util_name) + "\n\n"

    synopsis = separator("SYNOPSIS") + "\n" + "SYNOPSIS\n" + separator("SYNOPSIS") + "\n"
    synopsis += util_help.synopsis + "\n"

    description = separator("DESCRIPTION") + "\n"  + "DESCRIPTION\n" + separator("DESCRIPTION") + "\n"
    description += util_help.name + "\n\n"

    options = separator("OPTIONS") + "\n"  + "OPTIONS\n" + separator("OPTIONS") + "\n"
    options += util_help.options + "\n\n"

    examples = separator("EXAMPLES") + "\n"  + "EXAMPLES\n" + separator("EXAMPLES") + "\n"
    examples += util_help.examples + "\n\n"

    man = index_name_doc + synopsis + description + options + examples
    return man


def create_index(util_name):
    path_index = "source/indexes/"
    index_file_out = open(path_index + "virgil-" + util_name + ".rst", 'w')
    index = ".. toctree::\n" + "    ../virgil-cli/virgil-" + util_name + ".rst"
    index_file_out.write(index)
    index_file_out.close()


def add_man_page_to_conf_py(index, name, short_name_description, comma=""):
    path_conf_py = "source/conf.py"
    f_conf_py = open(path_conf_py, 'r')
    conf_py = ""
    for line in f_conf_py:
        conf_py += line

    man_start = conf_py.rfind("man_pages = [")
    new_man_page = "    (\"" + index + "\", \"" + name + "\", u\"" + re.sub(r'\s+', ' ', short_name_description) + "\", "
    new_man_page += "[author], 1)" + comma + "\n"

    new_conf_py = conf_py[0:man_start + 14] + new_man_page + conf_py[man_start + 14:]
    file_new_conf_py = open(path_conf_py, 'w')
    file_new_conf_py.write(new_conf_py)


def main():
    print("convert virgil utilname -h => sphinx-doc")

    # 1. Create indexes/name_util.rst
    # 2. Add toctree in index
    # .. toctree::
    #	../virgil-cli/virgil-name_util
    # 3.Add index + name + name_descr conf.py
    # man_pages = [
    #           ( 'indexes/virgil-name_util', 'virgil-name_util', u'name', [author], 1 )
    # ]

    # 1. find "man_pages = ["
    # man_pages = [
    #     (master_doc, 'virgil', u'virgil Documentation',
    #      [author], 1)
    # ]

    program = "virgil"
    arg_h = "-h"

    file_utils = open("utils.txt")
    utils = []
    for line in file_utils:
        if len(line) > 0 and line[0] != "#" and line[0] != "\n":
            utils.append(line.strip())

    path_source = "source/virgil-cli/"
    for util_name in utils:
        util_help = get_help([program, util_name, arg_h])
        create_index(util_name)
        man_page = create_man_page(util_name, util_help)

        source_file_out = open(path_source + program + "-" + util_name + ".rst", 'w')
        add_man_page_to_conf_py("indexes/virgil-" + util_name, "virgil-" + util_name, util_help.name, ",")

        for line in man_page:
            source_file_out.write(line)
        source_file_out.close()


if __name__ == "__main__":
    main()
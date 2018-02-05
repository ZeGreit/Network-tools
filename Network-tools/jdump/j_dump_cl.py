def nest_dict(dick, dict_nest_lvl, list_nest_lvl, ind_str):
    dict_nest_lvl += 1
    list_nest_lvl = dict_nest_lvl
    for k,v in dick.items():
        indent = ''
        if dict_nest_lvl > 1:
            for i in range(dict_nest_lvl - 1):
                indent += ind_str
        if isinstance(v, list):
            print(indent + k + ':')
            nest_list(v, list_nest_lvl, dict_nest_lvl, ind_str)
        elif isinstance(v, dict):
            print_lvl(indent + k + ':')
            nest_dict(v, dict_nest_lvl, list_nest_lvl, ind_str)
        else:
            print(indent + k + ' -> ' + str(v))

def nest_list(lst, list_nest_lvl, dict_nest_lvl, ind_str):
    list_nest_lvl += 1
    for line in lst:
        if isinstance(line, list):
            nest_list(line, list_nest_lvl, dict_nest_lvl, ind_str)
        elif isinstance(line, dict):
            nest_dict(line, dict_nest_lvl, list_nest_lvl, ind_str)
        else:
            indent = ''
            if list_nest_lvl > 1:
                for i in range(list_nest_lvl - 1):
                    indent += ind_str
            print(indent + line)

class json_text(object):

    def __init__(s, body):
        s.body = body

    def jdump(s, ind_len = 0):
        ind_str = ' '.join(' ' for i in range(int(ind_len)))
        list_nest_lvl = 0
        dict_nest_lvl = 0
        nest_dict(s.body, dict_nest_lvl, list_nest_lvl, ind_str)

    def __str__(s):
        return 'Frickin\' object'

# public
# static
# String
# judgeSQL(String
# str) {
#     String
# select = ".*SELECT.*";
# String
# where = ".*WHERE.*";
# String
# delete = ".*DELETE.*";
# String
# from = ".*FROM.*";
# String
# drop = ".*DROP.*";
# String
# table = ".*TABLE.*";
# if (str.matches(select) | | str.matches(where)
#     | | str.matches(delete) | | str.matches(from)
#    | | str.matches(drop) | | str.matches(table)) {
# return "SQLinject";
# }
# else {
# return "Normal";
# }
# }

import re

def judgeSQL(str):
    select = ".*SELECT.*"
    delete = ".*DELETE.*"
    where = ".*WHERE.*"
    _from = ".*FROM.*"
    drop = ".*DROP.*"
    table = ".*TABLE.*"
    if re.matches(select,str,re.I) or re.matches(where,str,re.I) or \
       re.matches(delete,str,re.I) or re.matches(_from,str,re.I) or \
        re.matches(drop,str,re.I) or re.matches(table,str,re.I):
        pass
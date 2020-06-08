#
#   Copyright (c) 2020 One Identity
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#


import re


class Filter():
    BLACKLIST_PATTERNS = ["(?I).*_password"]

    def __init__(self, obj):
        self._obj = obj

    def __getitem__(self, item):
        for pattern in self.BLACKLIST_PATTERNS:
            if re.match(pattern, item):
                raise KeyError("Acces to {} denied".format(item))
        return getattr(self._obj, item)

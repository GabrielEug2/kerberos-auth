
def has_keys(mydict, keys):
    if all(key in mydict for key in keys):
        return True
    else:
        return False

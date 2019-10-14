
def truncate(string, trunc_to=100):
    """
    Truncate string, by splitting in two parts and replace long content with "..." symbols
    :param string:
    :param trunc_to:
    :return:
    """
    if len(string) > trunc_to:
        return string[:trunc_to // 2] + '...' + string[len(string) - trunc_to // 2:]
    else:
        return string
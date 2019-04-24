def longint_to_str(data):
    if isinstance(data, (int, float)):
        data = str(data)
        return data
    elif type(data) == list:
        result = []
        for v in data:
            result.append(longint_to_str(v))
        return result
    elif type(data) == dict:
        result = {}
        for k, v in data.items():
            if isinstance(v, (int, float)):
                result[k] = str(v)
            elif type(v) == dict or type(v) == list:
                result[k] = longint_to_str(v)
            else:
                result[k] = v
        return result
    return data

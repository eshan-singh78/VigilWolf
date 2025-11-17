import re


def clean_log(s: str) -> str:
    if not s:
        return ''
    ansi_escape = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
    no_ansi = ansi_escape.sub('', s)
    no_ansi = no_ansi.replace('\r\n', '\n').replace('\r', '\n')
    no_ansi = re.sub(r"\n{2,}", '\n\n', no_ansi)
    return no_ansi.strip()

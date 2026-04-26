from pathlib import Path

for d in ['eden','eden/sensing','eden/oracle','eden/chain','eden/lex0']:
    Path(d).mkdir(exist_ok=True)
    (Path(d)/'__init__.py').touch()

print('Dirs OK')
for f in Path('eden').rglob('*'):
    print(' ',f)

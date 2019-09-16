#%%
import pandas as pd

def get_range():
    return range(25, 300 + 25, 25)

# clean the log
def clean_log(output_f, input_f):
    start_printing = False
    start = 'BEGIN EXPERIMENT'
    end = 'END OF EXPERIMENT'

    with open(output_f, 'w') as cleaned:
        for (type, file) in input_f.items():
            with open(file, 'r') as dirty:
                for (i, line) in enumerate(dirty):
                    if start in line:
                        start_printing = True
                    elif end in line:
                        start_printing = False
                    elif start_printing:
                        cleaned.write(' '.join(line.split(' ')[5:]))

#%%
input_f = {
    'sock_dtls': 'examples/fgsn19/log/sock-dtls-processing-time',
    # 'tinydtls' : '',
    # 'sock_udp' : '',
}
output_f = input_f['sock_dtls'] + '.csv'
clean_log(output_f, input_f)

df = pd.read_csv(output_f)
# TODO: add implementation type to log data
# TODO: swap dtls_time header with udp_time
# TODO: 'udp start' -> 'full start'
df['full time'] = df['end'] - df['full start']
df['dtls time'] = df['end'] - df['dtls start']

#%%
frames = {}
for size in get_range():
    frames[size] = df.loc[df['payload size'] == size]

columns = []
for (i) in get_range():
    columns.append("mean-" + str(i))
    columns.append("std-" + str(i))
index = ['sock_dtls', 'tinydtls', 'sock_udp']
full_time = pd.DataFrame(index=index, columns=columns)
full_time = full_time.fillna(0)

for size in get_range():
    full_time.at['sock_dtls', "mean-" + str(size)] = frames[size]['full time'].mean()
    full_time.at['sock_dtls', "std-" + str(size)] = frames[size]['full time'].std()

dtls_time = pd.DataFrame(index=index, columns=columns)
dtls_time = dtls_time.fillna(0)

for size in get_range():
    dtls_time.at['sock_dtls', "mean-" + str(size)] = (frames[size]['full time'] - frames[size]['dtls time']).mean()
    dtls_time.at['sock_dtls', "std-" + str(size)] = (frames[size]['full time'] - frames[size]['dtls time']).std()

#%%
import matplotlib as mpl
#matplotlib.use('pgf')
from matplotlib.backends.backend_pgf import FigureCanvasPgf
mpl.backend_bases.register_backend('pdf', FigureCanvasPgf)
import matplotlib.pyplot as plt

mpl.use("pgf")
pgf_with_custom_preamble = {
    "font.family": "serif",  # use serif/main font for text elements
    "text.usetex": True,     # use inline math for ticks
    "pgf.rcfonts": False,    # don't setup fonts from rc parameters
    "pgf.preamble": [
         "\\usepackage{units}",          # load additional packages
         "\\usepackage{metalogo}",
         "\\usepackage{unicode-math}",   # unicode math setup
         #"\\setmathfont{xits-math.otf}",
         #"\\setmainfont{DejaVu Serif}",  # serif font via preamble
         ]
}
mpl.rcParams.update(pgf_with_custom_preamble)


x = get_range()
for i in range(1): # TODO: change range to 3 when have all data
    # get row using iloc and convert it to array because pyplot expect array input

    # plot time taken for full network stack (DTLS included)
    y = full_time[list('mean-' + str(i) for i in get_range())].iloc[i].values
    e = full_time[list('std-' + str(i) for i in get_range())].iloc[i].values
    plt.errorbar(x, y, e)

    # plot time taken for DTLS operations
    y = dtls_time[list('mean-' + str(i) for i in get_range())].iloc[i].values
    e = dtls_time[list('std-' + str(i) for i in get_range())].iloc[i].values
    plt.errorbar(x, y, e)

plt.xlabel("Payload size / byte")
plt.ylabel("Processing time / ms")
plt.legend(['sock_dtls - DTLS + UDP + IP', 'sock_dtls - DTLS'])

plt.savefig('processing-time.pgf')
#%%

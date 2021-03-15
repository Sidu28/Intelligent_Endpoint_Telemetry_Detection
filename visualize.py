import os
import sys
import argparse
import uuid
import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt



def main():
    parser = argparse.ArgumentParser(description="Execute feature extraction for an input PE file")
    parser.add_argument('file', type=str, help="dataframe containing features of PE Files")
    args = parser.parse_args()

    df = pd.read_csv(args.file)
    '''
    for col_idx in range(0,10):
        col = df.iloc[:,col_idx]
        plt.hist(col, color='blue', edgecolor='black',
                 bins=int(180 / 5))
        plt.savefig(str(uuid.uuid4())+'.png')

    '''
    directory = os.path.join(os.getcwd(), 'images')
    if not os.path.isdir(directory):
        os.mkdir(directory)

    fig, axes = plt.subplots(ncols=10, figsize=(22.9, 5 ))
    for ax, col in zip(axes, df.columns):
        plot = sns.distplot(df[col], ax=ax)
    plt.savefig('images/'+str(uuid.uuid4())+".png")


if __name__ == '__main__':
  main()
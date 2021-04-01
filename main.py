import os
import sys
import argparse
import numpy as np
from pprint import pprint
import pandas as pd
import seaborn as sns
import random
import matplotlib.pyplot as plt

# PE file related imports
import pefile
# import lief

# Relevant modules
import feature_utils

numeric_feature_extractors = feature_utils.NUMERIC_FEATURE_EXTRACTORS
alphabetical_feature_extractors = feature_utils.ALPHABETICAL_FEATURE_EXTRACTORS

if __name__ == '__main__':

  parser = argparse.ArgumentParser(description="Execute feature extraction for an input PE file")
  parser.add_argument('--file', type=str, required=False, help="Input PE file to extract features for")
  parser.add_argument('--dir', type=str, required=False, help="Directory containing PE files to extract features for")
  parser.add_argument('--label', type=int, required=False, default=1, help="Label for the PE Files you are processing")
  parser.add_argument('--good', type=str, required=False, help="CSV of good PE file-features")
  parser.add_argument('--bad', type=str, required=False, help="CSV of bad PE file-features")

  args = parser.parse_args()

  #Creating a directory and naming for outputs
  name = str(random.randint(1111, 9999))
  directory_name = 'data_' + name
  directory = os.path.join(os.getcwd(), 'data')
  if not os.path.isdir(directory):
    os.mkdir(directory)

  os.chdir(os.getcwd()+'/data')

  #We either specify a large directory of files or a single file to examine
  if args.file and args.dir:
    parser.error('specify either directory or file')

  elif args.file:
    '''
    Print basic features for a specified file, both numeric and alphabetical features
    '''

    num_features = feature_utils.extract_features(args.file, numeric_feature_extractors)
    alpha_features = feature_utils.extract_features(args.file, alphabetical_feature_extractors)
    pprint("Numerical Features: ", num_features)
    pprint("Alphabetical/String Features: ", alpha_features)


  if args.dir:
    '''
    If a directory is specified, we iterate through it, extracting numerical features
    and saving them to a csv file which is in the 'data' directory
    '''

    rows = []

    for file in os.listdir(args.dir):
      if not file.startswith('.'):
        file = os.path.join(args.dir, file)
        features = {}

        try:
          features = feature_utils.extract_features(args.file, numeric_feature_extractors)
          rows.append(features)
        except Exception:
          continue

    # Create dataframe using the feature extractors
    df = pd.DataFrame(rows)
    df['label'] = args.label

    directory = os.path.join(os.getcwd(), directory_name)
    if not os.path.isdir(directory):
      os.mkdir(directory)

    df.to_csv(directory + '/features_' + name + ".csv")
    directory = os.path.join(os.getcwd(), directory_name+'/images')
    if not os.path.isdir(directory):
      os.mkdir(directory)

    # Plot the distributions of the important features
    fig, axes = plt.subplots(ncols=10, figsize=(22.9, 5))
    for ax, col in zip(axes, df.columns):
      plot = sns.distplot(df[col], ax=ax)
    plt.savefig(directory_name+'/images/image_' + name + ".png")


  elif args.good and args.bad:
    '''
    Extract good and bad features, save them separately as individual csv files
    '''
    df_good = pd.read_csv(args.good)
    df_bad = pd.read_csv(args.bad)
    common_cols = pd.Series(np.intersect1d(df_good.columns.values, df_bad.columns.values))
    name = str(random.randint(1111, 9999))
    df_good = df_good[common_cols]
    df_bad = df_bad[df_good.columns]
    df_comb = c = pd.concat([df_good, df_bad],ignore_index=True)
    df_comb.to_csv('features_good_bad'+name+'.csv')

    num_cols = len(df_good.columns)
    df_list = [df_good, df_bad]
    idx=0

    while idx < num_cols:

      for i,df in enumerate(df_list):
        fig, axes = plt.subplots(ncols=10, figsize=(22.9, 5))
        for ax, col in zip(axes, df.columns[idx:idx+10]):
          plot = sns.distplot(df[col], ax=ax)
        plt.savefig(directory_name+'/images/image_' + name +'_'+ str(i) + ".png")
      idx+=10

  else:
    parser.error('check your command line arguments')

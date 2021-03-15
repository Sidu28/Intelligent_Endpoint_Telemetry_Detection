import os
import sys
import argparse
import pandas as pd
import uuid
import uuid
import seaborn as sns
import matplotlib.pyplot as plt

# PE file related imports
import pefile
# import lief

# Relevant modules
from features.asm import ASMExtractor
from features.section_info import SectionInfoExtractor
from features.virustotal import VirusTotalExtractor

# Dictionary of available feature extractors, along with keyword arguments
feature_extractors = {
  ASMExtractor: None,
  SectionInfoExtractor: None,
  #VirusTotalExtractor: None # should the API key be a keyword argument?
}


def main():
  parser = argparse.ArgumentParser(description="Execute feature extraction for an input PE file")
  parser.add_argument('dir', type=str, help="Directory containing PE files to extract features for")
  args = parser.parse_args()

  rows = []

  for file in os.listdir(args.dir):
    if not file.startswith('.'):
      file = os.path.join(args.dir, file)
      features = {}
      for extractor in feature_extractors:
        kwargs = feature_extractors[extractor]
        e = extractor(file)
        features.update(e.extract(kwargs=kwargs))
          
      rows.append(features)

  df = pd.DataFrame(rows)
  df['label'] = 1

  directory = os.path.join(os.getcwd(), 'data')
  if not os.path.isdir(directory):
    os.mkdir(directory)


  df.to_csv(directory+'/features_'+str(uuid.uuid4())+".csv")
  '''
  for col_idx in range(0,10):
      col = df.iloc[:,col_idx]
      plt.hist(col, color='blue', edgecolor='black',
               bins=int(180 / 5))
      plt.savefig(str(uuid.uuid4())+'.png')

  '''
  directory = os.path.join(os.getcwd(), 'data/images')
  if not os.path.isdir(directory):
    os.mkdir(directory)

  fig, axes = plt.subplots(ncols=10, figsize=(22.9, 5))
  for ax, col in zip(axes, df.columns):
    plot = sns.distplot(df[col], ax=ax)
  plt.savefig('data/images/' + str(uuid.uuid4()) + ".png")

if __name__ == '__main__':
  main()

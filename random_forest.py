import os, sys
import pickle
import argparse

from category_encoders.binary import BinaryEncoder
from category_encoders.leave_one_out import LeaveOneOutEncoder
from category_encoders.target_encoder import TargetEncoder
from matplotlib import rcParams
import openpyxl  # for Excel exports
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import make_scorer
from sklearn.metrics import mean_squared_error
from sklearn.model_selection import GridSearchCV
from sklearn.model_selection import train_test_split, KFold
import numpy as np
import pandas as pd
from matplotlib import pyplot as plt



class RFPredictor(object):
    def __init__(self):

        self.script_dir = os.path.dirname(__file__)
        self.df = pd.read_csv('/Users/sidu/Downloads/vmware/features.csv')
        self.X = self.df.iloc[:,0:-1]
        self.y = self.df.iloc[:,-1]

        self.rand_forest = RandomForestRegressor()

    # ------------------------------------
    # run
    # -------------------

    def run(self):

        features = self.X.fillna(0)
        labels = self.y
        array, important_features = self.predict_one_election_kfolds(features, labels)

        rmse = []
        for (pred, truth) in array:
            rmse.append(self.evaluate_model(pred, truth))
        print(rmse)

        x = self.X.dropna(axis=1)
        '''
        fig = plt.figure(figsize=(10, 5))
        plt.barh(x.columns, important_features)
        plt.xlabel("Courses offered")
        plt.ylabel("No. of students enrolled")
        plt.title("Students enrolled in different courses")
        plt.show()
        '''

    # ------------------------------------
    # predict
    # -------------------

    def predict_one_election_kfolds(self, X_df, y_series):
        # KFolds cross-validation
        kf = KFold(n_splits=5, shuffle=True)
        KFold(n_splits=5)

        pred, truth = X_df, y_series

        rf_optimal_parms_path = os.path.join(self.script_dir, 'best_params.pickle')
        '''
        try:
            with open(rf_optimal_parms_path, 'rb') as fd:
                best_params = pickle.load(fd)
                # The '**' signals that best_params
                # is a dict, and should be used as
                # kwargs:
                self.rand_forest.set_params(**best_params)
        except FileNotFoundError:
            # No previously stored parms
            best_params = self.optimize_hyperparameters(self.X, self.y)
            with open(rf_optimal_parms_path, 'wb') as fd:
                # Save as a text format:
                pickle.dump(best_params, fd, protocol=0)
        '''
        pred_arr = []
        for train_idx, test_idx in kf.split(X_df):

            train_features_df = X_df.iloc[train_idx]
            train_labels_series = y_series.iloc[train_idx]
            test_features_df = X_df.iloc[test_idx]
            test_labels_series = y_series.iloc[test_idx]

            X_train = train_features_df.to_numpy(dtype=float)
            y_train = train_labels_series.to_numpy(dtype=float)
            X_test = test_features_df.to_numpy(dtype=float)
            y_test = test_labels_series.to_numpy(dtype=float)


            self.rand_forest.fit(X_train, y_train)

            important_features = self.rand_forest.feature_importances_

            predictions = self.rand_forest.predict(X_test)

            pred_series = pd.Series(predictions)
            truth_series = pd.Series(y_test)

            pred, truth = pred_series, truth_series
            pred_arr.append((pred, truth))

        return pred_arr, important_features

    # ------------------------------------
    # evaluate model
    # -------------------

    def evaluate_model(self, predictions, test_labels):
        rmse = (mean_squared_error(test_labels,
                                   predictions,
                                   squared=False
                                   ))
        return rmse

    # ------------------------------------
    # optimize hyper parameters
    # -------------------

    def optimize_hyperparameters(self, train_X, train_y):
        '''
        Takes a feature matrix and target, and returns
        a dictionary with the best Random Forest parameters.
        Assumes self.rand_forest is an uninitialized instance
        of RandomForestClassifier.

        Example of return: {'max_depth': 3, 'n_estimators': 8}

        @param train_X: feature matrix
        @type train_X: pd.DataFrame
        @param train_y: target vector
        @type train_y: pd.Series
        '''

        tuned_parameters = {  # ****'n_estimators' : 1+np.array(range(10)),
            'max_depth': 1 + np.array(range(3)),
            'n_estimators': 1 + np.array(range(10)),
            # ****'max_depth'    : 1+np.array(range(10))
        }
        scorer = make_scorer(mean_squared_error, greater_is_better=False)
        clf = GridSearchCV(
            self.rand_forest,
            tuned_parameters,
            scoring=scorer,
            cv=5,
            n_jobs=10,
            verbose=1
        )
        #train_X = train_X[:, ~np.all(np.isnan(train_X), axis=0)]

        clf.fit(train_X,
                train_y
                )
        self.rand_forest = clf.best_estimator_

        importances = self.rand_forest.feature_importances_
        # Associate the importances with their feature
        # names as tuples (<feature_name>, <importance>):
        feature_importances = list(zip(self.feature_names,
                                       importances
                                       ))
        sorted_importances = sorted(feature_importances,
                                    key=lambda name_imp_pair: name_imp_pair[1],
                                    reverse=True
                                    )

        return clf.best_params_


if __name__ == '__main__':
    '''
    parser = argparse.ArgumentParser(description="Execute feature extraction for an input PE file")
    parser.add_argument('file', type=str, help="file containing PE file features")
    args = parser.parse_args()
    '''

    RFPredictor().run()




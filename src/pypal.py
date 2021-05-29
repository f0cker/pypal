""""Pypal password analysis report generator"""

from pathlib import Path
import matplotlib.pyplot as plt
from nltk.probability import FreqDist
from nltk.stem import WordNetLemmatizer
import numpy as np
from tqdm import tqdm
from vega_datasets import data

import altair as alt
import json
import pandas

try:
    from cfuzzyset import cFuzzySet as FuzzySet
except ImportError:
    from fuzzyset import FuzzySet


class Report(object):
    """
    Class for creating password dump analysis reports

    Paramaters
    ---------
    lang: str
        String representing choice of language to use for
        base word check, i.e. AF, EN, ES, DE, IT, NN, FR, PL, RU
        or ALL for well all of them duh.
    lists: str
        String location of the lists directory under ./pypal/src.
        These are the dictionaries used by Pypal

    cracked_path: Path | str
        Pathlib Path or string path of cracked hashes to use for reporting on.

    Returns
    ---------
    state: str
        String representing the status of report generation
        i.e. None, Working, Generated
    """

    def __init__(self, cracked_path=None, lang='EN', lists=None,
                 hash_path=None):
        if type(cracked_path) == str:
            cracked_path = Path(cracked_path)
        if type(hash_path) == str:
            hash_path = Path(hash_path)
        self.cracked_path = cracked_path
        self.hash_path = hash_path
        self.name = cracked_path.stem
        self.file_dir = cracked_path.parent
        self.lang = lang
        self.pass_file = self.pass_format(cracked_path, hash_path=hash_path)
        self.lists = lists
        self.lang_dict = Path(lists).joinpath('{}_list.txt'.format(lang))
        self.country_dict = Path(lists).joinpath('Country_list.txt')
        self.city_dict = Path(lists).joinpath('City_list.txt')
        self.city_gps = Path(lists).joinpath('City_lonlat_list.csv')
        self.baselang_file = self.file_dir.joinpath('{}_basewords.txt'.format(
                                                     self.name))
        self.basecountry_file = self.file_dir.joinpath('{}_basecountry.txt'.format(
                                                       self.name))
        self.basecity_file = self.file_dir.joinpath('{}_basecity.txt'.format(
                                                     self.name))
        self.len_file = self.file_dir.joinpath('{}_len.txt'.format(
                                               self.name))
        self.stats_file = self.file_dir.joinpath('{}_stats.json'.format(
                                               self.name))

    def pass_format(self, cracked_path, hash_path=None):
        """
        Check the format of the cracked hash/password file
        and if required format it

        Arguments
        ---------
        cracked_path: Path
            location of cracked hashes file
        hash_path: Path
            location of original hash file

        Returns
        ------
        pass_file: Path/boolean
            Location of the formatted file or false if error
        """
        if self.cracked_path:
            with cracked_path.open('r', encoding='-8859-') as fh_cracked:
                pass_file = cracked_path.parent.joinpath(
                                '{}.clean'.format(self.name))
                with pass_file.open('w', encoding='-8859-') as fh_pass:
                    for line in fh_cracked:
                            for line in fh_cracked:
                                if len(line.split(':')) > 1:
                                        fh_pass.write(line.split(':')[-1])
                                else:
                                    pass_file = cracked_path
                                    break

        else:
            pass_file = False
        return pass_file

    def cleaner(self, word):
        """
        Recursively remove symbols and numbers from end of string

        Arguments
        --------
        word: String
            Word to strip

        Returns
        -------
        word: String
            Stripped word

        """
        if len(word) > 1:
            if not word[-1].isalpha():
                word = word[:-1]
                word = self.cleaner(word)
        return word

    def get_ntds_stats(self, words_file=None,
                       ntds_file=None, hash_file=None):

        """
        Load a ntds.dit file, hash list and cracked password list,
        then return basic information, such as:
            stats relating to ntds file:
                machine accounts count
                user accounts count
                accounts enabled count
            number of enabled users password matching supplied string/s (i.e., adm, admin)
            number of enabled users in group supplied in string (i.e., 'Domain Admins')
            number & percentage of passwords not compliant
            number of those which are disabled
            number & percentage of LM hashes
            number of accounts that are disabled
            all disabled accounts?
            cracked enabled only?

        Arguments
        --------
        words_file: Path
            Pathlib path to file containing passwords to analyse
        ntds_file: Path
            Pathlib path to extracted NTDS.dit file
        hash_file: Path
            Pathlib path to hashes file
        column: str
            Name of the colummn, usually 'Password'
        topx: int
            How many to show, default is top 10

        Returns
        ------
        fdist: list
            Frequency distribution stats
        """
        print('test')

    def get_stats(self, policy=None, match=None, ):
        """
        Load a hash list and cracked password list,
        then return basic information, such as:
            total hash count
            total cracked
            percentage cracked
            of which were duplicates
            number of and users with duplicate hashes
            number of and users with blank passwords

        Arguments
        --------
        policy: Dict
            Dictionary containing password policy for the domain, supports keys:
                length: int,

        match: List
            List of usernames which are considered sensitive (DA EA etc),
            these can be gathered with PowerView or other tools

        Returns
        ------
        stats_dict: Dict or False
            Dictionary containing the results, in the following format
            {'Sensitive Account Hashes': 36,
            'Sensitive Passwords Cracked': 1,
            'Total Hashes': 88803,
            'Total Cracked': 9045,
            'Duplicate Hashes': 780,
            'Duplicate Cracked Passwords': 462,
            'Blank Passwords': 3,
            'LM Hashes': 227}
        """
        if self.cracked_path:
            with self.cracked_path.open('r', encoding='-8859-') as fh_cracked:
                cracked = [line.strip('\n').split(':') for line in fh_cracked]
            if type(cracked[0]) == list and len(cracked[0]) == 4:
                # pwdump format
                df_cracked = pandas.DataFrame(cracked, columns=['User', 'UserID', 'LM', 'Hash'])
            elif type(cracked[0]) == list and len(cracked[0]) == 3:
                df_cracked = pandas.DataFrame(cracked, columns=['User', 'Hash', 'Password'])
            elif type(cracked[0]) == list and len(cracked[0]) == 2:
                df_cracked = pandas.DataFrame(cracked, columns=['Hash', 'Password'])
            else:
                print('Error creating dataframe')
        else:
            df_cracked = None
        if self.hash_path:
            with self.hash_path.open('r', encoding='-8859-') as fh_hashes:
                try:
                    hashes = [line.strip('\n').split(':')[0:4] for line in fh_hashes]
                except Exception as err:
                    print(err)
                    hashes = [line.strip('\n').split(':') for line in fh_hashes]
            if type(hashes[0]) == list and len(hashes[0]) == 4:
                # pwdump format
                df_hashes = pandas.DataFrame(hashes, columns=['User', 'UserID', 'LM', 'Hash'])
            elif type(hashes[0]) == list and len(hashes[0]) == 3:
                df_hashes = pandas.DataFrame(hashes, columns=['User', 'Hash', 'Password'])
            elif type(hashes[0]) == list and len(hashes[0]) == 2:
                df_hashes = pandas.DataFrame(hashes, columns=['Hash', 'Password'])
            else:
                print('Error creating dataframe')
        else:
            df_hashes = None
        if not all(type(df) == pandas.DataFrame for df in [df_hashes, df_cracked]):
            return False
        stats_dict = {}
        merged = pandas.merge(df_hashes, df_cracked, how='left', on='User')
        dupe_count = merged.duplicated(subset='Hash_x').sum()
        dupe_pass = merged[merged['Password'].notna()].duplicated(subset='Password').sum()
        blank_count = merged['Hash_x'].isin(['31d6cfe0d16ae931b73c59d7e0c089c0']).sum()
        total_cracked = merged['Password'].notna().sum()
        total = merged.shape[0]
        lm = merged[-merged['LM'].isin(['aad3b435b51404eeaad3b435b51404ee'])]
        lm_count = len(lm)
        if match:
            if type(match) == list:
                match_count = merged['User'].str.contains('|'.join(match)).sum()
                stats_dict['Sensitive Account Hashes'] = match_count
                match_pass = merged['Password'][merged['User'].str.contains('|'.join(match))].notna().sum()
                stats_dict['Sensitive Passwords Cracked'] = match_pass
            else:
                stats_dict['Sensitive Account Hashes'] = 0
                stats_dict['Sensitive Passwords Cracked'] = 0
        else:
            stats_dict['Sensitive Account Hashes'] = 0
            stats_dict['Sensitive Passwords Cracked'] = 0
        if policy:
            if type(policy) == dict:
                for key, val in policy:
                    if key == 'length':
                        pol_length = merged[merged['Password']].str.len().lt(val).sum()
                        stats_dict['Policy Non-compliant Passwords'] = pol_length
                    else:
                        stats_dict['Policy Non-compliant Passwords'] = 0
            else:
                stats_dict['Policy Non-compliant Passwords'] = 0
        else:
            stats_dict['Policy Non-compliant Passwords'] = 0
        stats_dict['Total Hashes'] = total
        stats_dict['Total Cracked'] = total_cracked
        stats_dict['Duplicate Hashes'] = dupe_count
        stats_dict['Duplicate Cracked Passwords'] = dupe_pass
        stats_dict['Blank Passwords'] = blank_count
        stats_dict['LM Hashes'] = lm_count
        with open(self.stats_file, 'w') as fh_stat:
            fh_stat.write(json.dumps(str(stats_dict)))
        return stats_dict

    def get_freq(self, column=None, topx=None, words_file=None):
        """
        Load a password list and return frequency distribution

        Arguments
        --------
        words_file: Path
            Pathlib path to file containing passwords to analyse
        column: str
            Name of the colummn, usually 'Password'
        topx: int
            How many to show, default is top 10

        Returns
        ------
        fdist: list
            Frequency distribution stats
        """
        with words_file.open('r', encoding='-8859-') as fh_words:
            words_list = [word.strip('\n') for word in fh_words]
        fdist = FreqDist(words_list)
        df_com = pandas.DataFrame(fdist.most_common(topx),
                                  columns=[column, 'Count'])
        return df_com

    def base_check(self, dict_list, word_list, lem=True):
        """
        Check probability that the word is based on a dictionary word

        Arguments
        ---------
        dict_list: list
            list containing pre-loaded language dictionary
        word_list: list
            list containing the passwords to check
        lem: Boolean
            Select whether or not to use lemmatization,
            disable this for matching countries

        Returns
        -------
        word, score: tuple
            Generator where yield is a list of tuples
            containing base word and score
        """
        fuzz = FuzzySet(dict_list)
        lemm = WordNetLemmatizer()
        for word in word_list:
            word = self.cleaner(word)
            score = fuzz.get(word.lower())
            if lem:
                try:
                    lem_word = lemm.lemmatize(score[0][1])
                except TypeError:
                    lem_word = ""
            else:
                lem_word = ""
            yield (word, score, lem_word)

    def dict_checker(self, check_dict, out_file,
                     min_score=0.7, col='Base Word', lem=True):
        """
        This method will take a list of passwords from a file and
        fuzzy match against a language or other dictionary file.

        Arguments
        --------
        check_dict: Path
            Pathlib Path to language or other dictionary

        pass_file: Path
            Pathlib Path to cracked passwords file

        out_file: Path
            Pathlib Path to output file to save analysis data

        col: String
            Column name for matched word, i.e. country, word etc

        min_score: Float 
            threshold for minimum score, all words scoring
            below this will be marked as unmatched against a
            dictionary word. Default is 0.7 but this needs tweaking

        Returns
        -------
        freq_df: DataFrame/False
            Frequency dataframe
        """
        try:
            with check_dict.open('r', encoding='-8859-') as fh_dict:
                dict_list = [line.strip('\n') for line in fh_dict]
            with self.pass_file.open('r', encoding='-8859-') as fh_pass:
                pass_list = [line.strip('\n') for line in fh_pass]
            checker = self.base_check(dict_list, pass_list, lem=lem)
            with out_file.open('w') as fh_export:
                for check in tqdm(checker, total=len(pass_list)):
                    if isinstance(check[1], list):
                        score, word = check[1][0]
                        if score > min_score:
                            fh_export.write(word + '\n')
            freq_df = self.get_freq(column=col,
                                    topx=10, words_file=out_file)
            return freq_df

        except IOError as err:
            print('Error reading file: {}'.format(err))
            return False

    def gps_lookup(self, loc):
        """
        Take location name string (city) and look it up in 
        the gps list.

        Arguments
        --------
        loc: String
            Location to lookup

        Returns
        -------
        gps: Tuple
            (Float, FLoat) representing the gps cooardinates of 
            the provided location string
        """
        try:
            gps_df = pandas.read_csv(str(self.city_gps))
            gps_df = pandas.merge(gps_df, loc, on='City')
            return gps_df
        except IOError:
            print('Error opening list file')
            return False
        except TypeError:
            print('Error: no match found')
            return False

    def build_geograph(self, dframe=None):
        """
        Build the chart in Altair

        Arguments
        ---------
        dframe: pandas.DataFrame
            Data frame containing frequency analysis
            of passwords based on cities from freq_check

        Returns
        -------
        status: object
            Chart object or False
        """
        try:
            source = alt.topo_feature(data.world_110m.url, 'countries')
            # background map
            background = alt.Chart(source).mark_geoshape(
                fill='lightgray',
                stroke='white'
            ).properties(
                width=1000,
                height=600
            ).project('equirectangular')
            # city positions on background
            points = alt.Chart(dframe).transform_aggregate(
                latitude='mean(Latitude)',
                longitude='mean(Longitude)',
                count='mean(Count)',
                groupby=['City']
            ).mark_circle(opacity=0.6).encode(
                longitude='longitude:Q',
                latitude='latitude:Q',
                size=alt.Size('count:Q',
                    #scale=alt.Scale(range=[100, int(dframe['Count'].max())], zero=False),
                              scale=alt.Scale(range=[50, 3000], zero=False),
                              title='Scale of passwords'),
                color=alt.value('steelblue'),
                tooltip=['City:N', 'count:Q']
            ).properties(
                title='Geolocation Chart of Matched Passwords Based on City Names')
                #chart.title = title
                #chart.width = 1000
                #chart.height = 600
            return (background + points)
        except IOError as err:
            print('File load error: {}'.format(err))
            return False

    def build_graph(self, dframe=None, title=None, graph_type=None,
                    x_key=None, y_key=None):
        """
        This method will plot the chose chart using altair

        Arguments
        ---------
        dframe: pandas.DataFrame
            Data frame containing frequency analysis from freq_check
        title: str
            Name/title of the chart
        graph_type: str
            Type of chart, e.g. 'bar'
        x_key: str
            Name of the x axis
        y_key: str
            Name of the y axis

        Returns
        -------
        status: object
            Chart object or False
        """
        try:
            x_key_sort = alt.X(x_key,
                               sort=alt.EncodingSortField(
                                   field=x_key,
                                   order='ascending'))
            if graph_type == 'bar':
                chart = alt.Chart(dframe).mark_bar().encode(x=x_key_sort,
                                                            y=y_key)
                dframe.plot.bar(y=y_key, x=x_key, rot=0)
            elif graph_type == '':
                pass
            chart.title = title
            chart.width = 800
            chart.height = 500
            return chart
        except IOError as err:
            print('File load error: {}'.format(err))
            return False

    def check_len(self):
        """
        Check the length of each line entry in a file

        Arguments
        --------
        pass_file: Path
            File containing passwords to check length of
        len_file: Path
            File to write stats to
        Returns
        -------
        status: object
            Chart object or False
        """
        try:
            with self.pass_file.open('r',
                                     encoding='-8859-') as fh_pass_file:
                with open(self.len_file, 'w') as fh_out_file:
                    for passwd in fh_pass_file:
                        fh_out_file.write(str(len(passwd.strip())) + '\n')
            freq_df = self.get_freq(column='Length',
                                    topx=10, words_file=self.len_file)
            return freq_df

        except IOError as err:
            print('File load error: {}'.format(err))
            return False

    def report_gen(self):
        """
        Method to generate HTML reports

        This will write html to a file and return a status dictionary
        showing an report failures

        Arguments
        ---------
        image: list
            List of (str) image path locations to insert into report

        Returns
        -------
        report_status: dict
            Dict containing entries relating to report generation
            status and location of the final report file
        """
        report_template = """
            <!DOCTYPE html>
            <html>
            <head>
            <script src="https://cdn.jsdelivr.net/npm/vega@{vega_version}"></script>
            <script src="https://cdn.jsdelivr.net/npm/vega-lite@{vegalite_version}"></script>
            <script src="https://cdn.jsdelivr.net/npm/vega-embed@{vegaembed_version}"></script>
            </head>
            <title>
            CrackQ Password Analysis Report
            </title>
            <body>
            <div class="header">
            <h1>CrackQ Password Analysis Report</h1>
            </div>
            <br><br>
            <div id="vis1"></div>
            <br><br>
            <div id="vis2"></div>
            <br><br>
            <div id="vis3"></div>
            <br><br>
            <div id="vis4"></div>
            <br><br>
            <div id="vis5"></div>
            <br><br>
            <div id="vis6"></div>
            <script type="text/javascript">
              vegaEmbed('#vis1', {spec1}).catch(console.error);
              vegaEmbed('#vis2', {spec2}).catch(console.error);
              vegaEmbed('#vis3', {spec3}).catch(console.error);
              vegaEmbed('#vis4', {spec4}).catch(console.error);
              vegaEmbed('#vis5', {spec5}).catch(console.error);
              vegaEmbed('#vis6', {spec6}).catch(console.error);
            </script>
            </body>
            </html>
            """
        # generate freq distribution graph (top x passwords)
        freq_df = self.get_freq(column='Password',
                                topx=10, words_file=self.pass_file)
        if type(freq_df) == pandas.DataFrame:
            top_chart = self.build_graph(freq_df, title="Top 10 Passwords",
                                         graph_type='bar', x_key='Password',
                                         y_key='Count')
        # generate base words stats and graph
        base_freq = self.dict_checker(self.lang_dict,
                                      self.baselang_file,
                                      #lem=False
                                      col='Base Word')
        if type(base_freq) == pandas.DataFrame:
            base_chart = self.build_graph(base_freq,
                                          title='Top 10 Passwords by Base '
                                                'Words (English)',
                                          graph_type='bar',
                                          x_key='Base Word', y_key='Count')
        # generate word length stats and graph
        len_freq = self.check_len()
        if type(len_freq) == pandas.DataFrame:
            len_chart = self.build_graph(len_freq, title='Top 10 Password Lengths',
                                         graph_type='bar', x_key='Length',
                                         y_key='Count')
        # generate country based words stats and graph
        country_freq = self.dict_checker(self.country_dict,
                                         self.basecountry_file,
                                         col='Country',
                                         min_score=0.9,
                                         lem=False)
        if type(country_freq) == pandas.DataFrame:
            country_chart = self.build_graph(country_freq,
                                             title="Top 10 Passwords by country",
                                             graph_type='bar',
                                             x_key='Country', y_key='Count')
        # generate city based words stats and graph
        city_freq = self.dict_checker(self.city_dict,
                                      self.basecity_file,
                                      col='City',
                                      min_score=0.9,
                                      lem=False)
        if type(city_freq) == pandas.DataFrame:
            city_chart = self.build_graph(city_freq,
                                          title="Top 10 Passwords by city",
                                          graph_type='bar',
                                          x_key='City', y_key='Count')
        gps_df = self.gps_lookup(city_freq)
        if type(gps_df) == pandas.DataFrame:
            city_gps_chart = self.build_geograph(dframe=gps_df)
        try:
            with open(self.pass_file.parent.joinpath('{}_report.html'.format(
                      self.pass_file.stem)), 'w') as fh_report:
                fh_report.write(report_template.format(
                    vega_version=alt.VEGA_VERSION,
                    vegalite_version=alt.VEGALITE_VERSION,
                    vegaembed_version=alt.VEGAEMBED_VERSION,
                    spec1=top_chart.to_json(indent=None),
                    spec2=len_chart.to_json(indent=None),
                    spec3=base_chart.to_json(indent=None),
                    spec4=country_chart.to_json(indent=None),
                    spec5=city_chart.to_json(indent=None),
                    spec6=city_gps_chart.to_json(indent=None)
                ))
        except Exception as err:
            print('Failed to generate HTML report: {}'.format(err))
        ret_dict = {}
        ret_dict['topx_chart'] = json.loads(top_chart.to_json(indent=None)) if top_chart else None
        ret_dict['len_chart'] = json.loads(len_chart.to_json(indent=None)) if len_chart else None
        ret_dict['base_chart'] = json.loads(base_chart.to_json(indent=None)) if base_chart else None
        ret_dict['country_chart'] = json.loads(country_chart.to_json(indent=None)) if country_chart else None
        ret_dict['city_chart'] = json.loads(city_chart.to_json(indent=None)) if city_chart else None
        ret_dict['city_gps_chart'] = json.loads(city_gps_chart.to_json(indent=None)) if city_gps_chart else None
        return ret_dict


class DonutGenerator(object):
    """
    This class creates a nested donut chart containing an analysis
    of the results of the password cracking process

    """
    def __init__(self, source_data):
        # chart config
        self.outer_colors = ['#CCFFCC', '#FFE14D', '#FF8C19', '#B3FF66']
        self.mid_colors = ['#66FF66', '#FF1919', '#FF884D', '#FF3377']
        self.inner_colors = ['#FFFFFF', '#FF8C19', '#FF1919', '#CC0000', '#FF4019']
        self.wedgeprops = {'linewidth': 1, 'edgecolor': "w"}
        self.textprops = {'fontweight': 'bold', 'fontsize': 12, 'color': '#BDBDBD'}
        self.fig, self.ax = plt.subplots(subplot_kw=dict(aspect="auto"))
        self.text_invis = {'visible': False}
        self.source_data = source_data
        self.fig.set_size_inches(7, 14)

    def gen_donut(self):
        # overall hashes info chart
        total_other_list = [
            self.source_data['Duplicate Hashes'],
            self.source_data['LM Hashes'],
            self.source_data['Sensitive Account Hashes'],
            ]
        total_list = [(self.source_data['Total Hashes'] - sum(total_other_list))]
        total_list.extend(total_other_list)
        total_data = pandas.DataFrame({'Total Hashes': total_list})
        labels = [
                'Standard Account Hashes: {}'.format(total_list[0]),
                'Duplicate Hashes: {}'.format(total_list[1]),
                'LM Hashes: {}'.format(total_list[2]),
                'Sensitive Account Hashes: {}'.format(total_list[3])
                ]
        wedges, texts = self.ax.pie(total_data['Total Hashes'], startangle=45,
                                    labels=labels,
                                    colors=self.outer_colors, radius=1.0, labeldistance=1.35,
                                    wedgeprops=self.wedgeprops, textprops=self.text_invis)
        bbox_props = dict(fc='w', ec='w', lw=7.72, boxstyle='round')
        kw = dict(arrowprops=dict(arrowstyle="-", color="#BDBDBD", lw=2),
                  bbox=bbox_props, zorder=0)
        lab = 0
        move = 0
        for p in wedges:
            if total_data['Total Hashes'][lab] > 0:
                ang = (p.theta2 - p.theta1)/2. + p.theta1
                y = np.sin(np.deg2rad(ang))
                x = np.cos(np.deg2rad(ang))
                horizontalalignment = {-1: "right", 1: "left"}[int(np.sign(x))]
                connectionstyle = "angle,angleA=0,angleB={}".format(ang)
                kw["arrowprops"].update({"connectionstyle": connectionstyle})
                self.ax.annotate(labels[lab],
                                 color='#BDBDBD', weight='bold',
                                 xy=(x, y),
                                 xytext=(1.65*np.sign(x), (1.3*y)+move),
                                 horizontalalignment=horizontalalignment, **kw)
                move += 0.2
            lab += 1

        # overview chart
        over_list = [(self.source_data['Total Hashes'] - self.source_data['Total Cracked']), self.source_data['Total Cracked']]
        overview = pandas.DataFrame({'Overview': over_list})
        labels = [
                'Uncracked Hashes: {}'.format(over_list[0]),
                'Cracked Passwords: {}'.format(over_list[1])
                ]
        textprops = {'fontweight': 'bold', 'fontsize': 12, 'color': '#919191'}
        wedges, texts, texts1 = self.ax.pie(overview['Overview'], labels=labels,
                             startangle=90, pctdistance=0.64,
                             colors=self.mid_colors, autopct='(%1.1f%%)', radius=0.70, labeldistance=0.78,
                             wedgeprops=self.wedgeprops, textprops=textprops)
        for t in texts:
            t.set_horizontalalignment('center')
        bbox_props = dict(fc='w', ec='w', lw=7.72, boxstyle='round')
        kw = dict(arrowprops=dict(arrowstyle="-", color="#BDBDBD", lw=2),
                  bbox=bbox_props, zorder=0, va="center")

        # cracked password chart
        cracked_other_list = [
            self.source_data['Duplicate Cracked Passwords'],
            self.source_data['Blank Passwords'],
            self.source_data['Sensitive Passwords Cracked'],
            self.source_data['Policy Non-compliant Passwords'],
            ]
        cracked_list = [(self.source_data['Total Cracked'] - sum(cracked_other_list))]
        cracked_list.extend(cracked_other_list)
        cracked_data = pandas.DataFrame({'Total Cracked': cracked_list})
        labels = [
                'Cracked Passwords: {}'.format(cracked_list[0]),
                'Duplicate Passwords: {}'.format(cracked_list[1]),
                'Blank Passwords: {}'.format(cracked_list[2]),
                'Sensitive Passwords Cracked: {}'.format(cracked_list[3]),
                'Policy Non-compliant Passwords: {}'.format(cracked_list[4])
                ]
        wedges, texts, texts1 = self.ax.pie(cracked_data['Total Cracked'], startangle=-45,
                                            labels=labels,
                                            colors=self.inner_colors, autopct='(%1.1f%%)', radius=0.40, labeldistance=0.05,
                                            wedgeprops=self.wedgeprops, textprops=self.text_invis)
        for t in texts:
            t.set_horizontalalignment('left')
        bbox_props = dict(fc='w', ec='w', lw=7.72, boxstyle='round')
        kw = dict(arrowprops=dict(arrowstyle="-", color="#BDBDBD", lw=2),
                  bbox=bbox_props, zorder=0, va="center")
        lab = 0
        move = 0
        for p in wedges:
            if 'Cracked Passwords' not in labels[lab] and cracked_data['Total Cracked'][lab] > 0:
                ang = (p.theta2 - p.theta1)/2. + p.theta1
                y = np.sin(np.deg2rad(ang))
                x = np.cos(np.deg2rad(ang))
                connectionstyle = "angle,angleA=0,angleB={}".format(ang)
                horizontalalignment = {-1: "right", 1: "left"}[int(np.sign(x))]
                self.ax.annotate(labels[lab],
                             color='#BDBDBD', weight='bold',
                             xy=(0.4*x, 0.4*y),
                             xytext=(1.65*np.sign(x), (1.3*y)+move),
                             horizontalalignment=horizontalalignment, **kw)
                self.ax.figure.texts.append(self.ax.texts.pop())
                move += 0.2
            lab += 1

        # set the donut
        circle = plt.Circle((0, 0), 0.15, fc='white')
        self.fig.gca().add_artist(circle)
        #plt.tight_layout()
        handles, labels = self.ax.get_legend_handles_labels()
        labels.pop(6)
        handles.pop(6)
        leg = self.ax.legend(handles, labels)
        leg._fontsize = 14
        leg.set_title('Password Analysis Legend')
        leg.set_bbox_to_anchor((1.4, 0, 0, 0))
        for text in leg.get_texts():
            text.set_color('#919191')

        plt.title('AD Password Analysis',
                  fontdict={'fontsize': 14,
                            'fontweight': 'bold',
                            'color': '#BDBDBD'})
        return plt


if __name__ == '__main__':
    lang = 'EN'
    cracked_path = Path('../tests/test_customer_domain.cracked')
    hash_path = Path('../tests/test_customer_domain.hashes')
    report = Report(cracked_path=cracked_path,
                    lang=lang, lists='./lists/', hash_path=hash_path)
    gen = report.report_gen()
    stats = report.get_stats(match=['admin', 'svc'])
    donut = DonutGenerator(stats)
    donut = donut.gen_donut()
    donut.savefig('../tests/test_donut.svg', bbox_inches='tight', dpi=500)

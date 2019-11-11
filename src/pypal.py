""""Pypal password analysis report generator"""

from pathlib import Path
from nltk.probability import FreqDist
from nltk.stem import WordNetLemmatizer
from tqdm import tqdm
from vega_datasets import data

import altair as alt
import json
import pandas

try:
    from cfuzzyset import cFuzzySet as FuzzySet
except ImportError:
    from fuzzyset import FuzzySet


class Report():
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

    cracked_path: Path
        Pathlib Path of cracked hashes to use for reporting on.

    Returns
    ---------
    state: str
        String representing the status of report generation
        i.e. None, Working, Generated
    """

    def __init__(self, cracked_path=None, lang='EN', lists=None):
        self.name = cracked_path.stem
        self.file_dir = cracked_path.parent
        self.lang = lang
        self.pass_file = self.pass_format(cracked_path)
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

    def pass_format(self, cracked_path):
        """
        Check the format of the cracked hash/password file
        and if required format it

        Returns
        ------
        pass_file: Path
            Location of the formatted file
        """
        with cracked_path.open('r', encoding='-8859-') as fh_cracked:
            sample = [next(fh_cracked) for i in range(10)]
            score = {
                'username_score': 0,
                'hashpass_score': 0,
                'justpass_score': 0,
                }
            for line in sample:
                if line.count(':') > 1:
                    score['username_score'] += 1
                elif line.count(':') == 1:
                    score['hashpass_score'] += 1
                else:
                    score['justpass_score'] += 1
            file_type = max(score.keys(), key=(lambda k: score[k]))
            if file_type == 'username_score' and sample[1].count(':') != 2:
                raise SyntaxError('Invalid password file format')
            fh_cracked.seek(0)
            pass_file = cracked_path.parent.joinpath(
                                                    '{}.clean'.format(self.name))
            with pass_file.open('w', encoding='-8859-') as fh_pass:
                if file_type == 'hashpass_score':
                    for line in fh_cracked:
                        fh_pass.write(line.split(':')[-1])
                elif file_type == 'username_score':
                    for line in fh_cracked:
                        fh_pass.write(line.split(':')[2])
                else:
                    pass_file = cracked_path
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

    def base_check(self, dict_list, word_list,
                   lem=True):
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
                    #print(check)
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
            Pathfile Path to file containing passwords to check length of
        len_file: Path
            Pathfile Path to file to write stats to
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
                        fh_out_file.write(str(len(passwd)) + '\n')
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
        top_chart = self.build_graph(freq_df, title="Top 10 Passwords",
                                     graph_type='bar', x_key='Password',
                                     y_key='Count')
        # generate base words stats and graph
        base_freq = self.dict_checker(self.lang_dict,
                                      self.baselang_file,
                                      col='Base Word')
        base_chart = self.build_graph(base_freq,
                                      title='Top 10 Passwords by Base'
                                            'Words (English)',
                                      graph_type='bar',
                                      x_key='Base Word', y_key='Count')
        # generate word length stats and graph
        len_freq = self.check_len()
        len_chart = self.build_graph(len_freq, title='Top 10 Password Lengths',
                                     graph_type='bar', x_key='Length',
                                     y_key='Count')
        # generate country based words stats and graph
        country_freq = self.dict_checker(self.country_dict,
                                         self.basecountry_file,
                                         col='Country',
                                         min_score=0.9,
                                         lem=False)
        #print(country_freq)
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
        #print(city_freq)
        city_chart = self.build_graph(city_freq,
                                      title="Top 10 Passwords by city",
                                      graph_type='bar',
                                      x_key='City', y_key='Count')
        gps_df = self.gps_lookup(city_freq)
        #print(gps_df)
        city_gps_chart = self.build_geograph(dframe=gps_df)
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
                spec6=city_gps_chart.to_json(indent=None),
            ))
            return {'topx_chart': json.loads(top_chart.to_json(indent=None)),
                    'len_chart': json.loads(len_chart.to_json(indent=None)),
                    'base_chart': json.loads(base_chart.to_json(indent=None)),
                    'country_chart': json.loads(country_chart.to_json(indent=None)),
                    'city_chart': json.loads(city_chart.to_json(indent=None)),
                    'city_gps_chart': json.loads(city_gps_chart.to_json(indent=None))}


if __name__ == '__main__':
    import nltk
    nltk.download('wordnet')
    cracked_path = Path('../tests/5k_linkedin_sample.txt')
    lang = 'EN'
    report = Report(cracked_path=cracked_path, lang=lang, lists='./lists/')
    gen = report.report_gen()
    #print(gen)

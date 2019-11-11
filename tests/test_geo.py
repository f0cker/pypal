import altair as alt
from vega_datasets import data
import pandas
import sys

cities = pandas.read_csv(sys.argv[1])
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
points = alt.Chart(cities).transform_aggregate(
    latitude='mean(latitude)',
    longitude='mean(longitude)',
    count='mean(Count)',
    groupby=['City']
).mark_circle(opacity=0.6).encode(
    longitude='longitude:Q',
    latitude='latitude:Q',
    size=alt.Size('count:Q',
        #scale=alt.Scale(range=[100, int(cities['Count'].max())], zero=False),
        scale=alt.Scale(range=[50, 3000], zero=False),
        title='Scale of passwords'),
    color=alt.value('steelblue'),
    tooltip=['City:N', 'count:Q']
).properties(
    title='Geolocation Chart of Matched Passwords Based on City Names')

(background + points).save(sys.argv[2] + 'geo_chart.html')

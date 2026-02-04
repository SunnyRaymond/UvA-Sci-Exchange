import pandas as pd


def get_df() -> pd.DataFrame:
    df = pd.DataFrame(
        data=[
            ['Lettuce', 'Vegetables', 0.82, '1 pc', 5],
            ['Broccoli', 'Vegetables', 1.29, '500 gr', 3],
            ['Carrot', 'Vegetables', 0.45, '1 pc', 22],
            ['Eggplant', 'Vegetables', 0.72, '1 pc', 1],
            ['Spaghetti', 'Pastas', 0.99, '500 gr', 0],
            ['Tagliatelle', 'Pastas', 1.89, '500 gr', 2],
            ['Penne', 'Pastas', 0.99, '500 gr', 3],
            ['Rice', 'International', 2.59, '1 kg', 7],
            ['Coffee', 'Breakfast', 7.49, '1 kg', 10],
            ['Juice', 'Breakfast', 2.79, '2 L', 3],
            ['Apple', 'Fruits', 2.39, '1 kg', 6],
            ['Banana', 'Fruits', 1.49, '500 gr', 2],
            ['Strawberry', 'Fruits', 3.49, '400 gr', 10],
        ],
        columns=['Product', 'Category', 'Price', 'Unit', 'Stock'],
    )
    
    df.set_index('Product', inplace=True)
    df.index.name = None
    df.sort_index(inplace=True)

    return df

def get_stocks() -> pd.DataFrame:
    df = pd.DataFrame.from_dict(
        data = {
            'columns':['Carrot', 'Apple', 'Coffee', 'Lettuce'],
            'index': pd.DatetimeIndex([
                "2023/08/07","2023/08/14","2023/08/21","2023/08/28","2023/09/04",
                "2023/09/11","2023/09/18","2023/09/25","2023/10/02","2023/10/09"
            ]),
            'data': [[   7,   17,   13,   22],
                     [None,   12, None,   17],
                     [None,    9,    7,    9],
                     [None,    5,    3,    5],
                     [  38,   20,   17,   22],
                     [  22,   12,   14,   16],
                     [  11, None,   12,   10],
                     [   3, None,    9,    3],
                     [  44,   23,   15,   14],
                     [  28,   10,   11,    8]],
            'index_names':['Date'],
            'column_names':['Product']
        },
        orient='tight',
        dtype=float,
    )

    df.sort_index(inplace=True)

    return df

def test_1(df:pd.DataFrame) -> None:
    """Test for exercise"""

    # Make sure its even a dataframe
    assert isinstance(df, pd.DataFrame), "❌ The variable `df` is not a DataFrame"
    print("✅ `df` is a DataFrame")

    # Set up answer in a sightly obfuscated way
    other = pd.DataFrame.from_dict({'X':['foo',5.3],'Z':['baz',.2],'Y':['bar',2.]}, orient='index', columns=['B','A'])
    cols = sorted(other.columns.tolist())
    idxs = sorted(other.index.tolist())

    # Order doesnt matter -> use a set to compare columns and indices
    assert set(cols) == set(df.columns), f"❌ `df` does not consist of columns {cols}"
    print("✅ `df` has columns", cols)

    assert set(idxs) == set(df.index), f"❌ `df` does not have indices {idxs}"
    print("✅ `df` has indices", idxs)

    # Now that columns/indices match, we can use df.eq to compare each value
    assert all(df.eq(other)), "❌ Not every value in `df` is correct"
    print("✅ `df` has correct values")

    # Also make sure dtypes are correct
    # NOTE: there is a possibility that `other` uses `float32` as dtype, while `df` uses `float64`
    # This should only occur if student specifies a different dtype than their computer uses by default
    # and can be resolved by not specifying a dtype in the notebook or specifying the same dtype here
    assert all(other[col].dtype == df[col].dtype for col in cols), f"❌ Not every column in `df` has the right dtype, `df` has types:\n{df.dtypes}"
    print("✅ `df` has correct dtypes")

def test_4(profits:pd.Series, total_profit:float) -> None:
    """
    Test for exercise

    NOTE: this only tests structure, not the actual values!!
    """

    # Make sure its a Series
    assert isinstance(profits, pd.Series), "❌ `profits` should be a Series"
    print("✅ `profits` is a Series")

    # With the same index as `df`
    assert set(profits.index) == set(get_df().index), "❌ `profits` should have the same index as `df`"
    print("✅ `profits` has the same index as `df`")

    # With float values
    assert profits.dtype == float, "❌ `profits` should have a float dtype"
    print("✅ `profits` has dtype float")

    # This should be a float too
    assert isinstance(total_profit, float), "❌ `total_profit` should be a float"
    print("✅ `total_profit` is a float")

    print("Note: did not check if the values are correct, try to check this for yourself!")


def test_9(price_diff:pd.Series) -> None:
    """
    Test for exercise

    NOTE: this only tests structure, not the actual values!!
    """

    # Make sure its a Series
    assert isinstance(price_diff, pd.Series), "❌ `price_diff` should be a Series"
    print("✅ `price_diff` is a Series")

    # With dtype float
    assert price_diff.dtype == float, "❌ `price_diff` should have a float dtype"
    print("✅ `price_diff` has a dtype float")

    # It needs to include all indices from `df`
    assert set(get_df().index).issubset(price_diff.index), "❌ `price_diff` does not include all indices of `df`"
    print("✅ `price_diff` includes all indices of `df`")

    # And not include any other indices
    assert not (set(price_diff.index) - set(get_df().index)), "❌ `price_diff` includes indices that are not in `df`"
    print("✅ `price_diff` does not contain any index that is not in `df`")

    print("Note: did not check if the values are correct, try to check this for yourself!")

def test_11(df_sorted:pd.DataFrame):
    """Test for exercise"""

    # Should be a DataFrame
    assert isinstance(df_sorted, pd.DataFrame), "❌ `df_sorted` should be a DataFrame"
    print("✅ `df_sorted` is a DataFrame")

    # With the same index and columns as df
    assert set(df_sorted.index) == set(get_df().index), "❌ `df_sorted` should have the same index as `df`"
    assert set(df_sorted.columns) == set(get_df().columns), "❌ `df_sorted` should have the same columns as `df`"
    print("✅ `df_sorted` has the same columns and index as `df`")

    # First difference should be negative, ie sorted in descending order
    assert all( df_sorted['Price'].diff()[1:] <= 0 ), "❌ The 'Price' column should be sorted in descending order"
    print("✅ `df_sorted` 'Price' column is in descending order")


def test_13(constant_fill:pd.DataFrame) -> None:
    """Test for exercise"""

    # Should be a DataFrame
    assert isinstance(constant_fill, pd.DataFrame), "❌ `constant_fill` should be DataFrame"
    print("✅ `constant_fill` is a DataFrame")

    # With same index and columns
    assert set(constant_fill.index) == set(get_stocks().index), "❌ `constant_fill` should have the same index as `stocks`"
    assert set(constant_fill.columns) == set(get_stocks().columns), "❌ `constant_fill` should have the same columns as `stocks`"
    print("✅ `constant_fill` has the same columns and index as `stocks`")

    # And no NaN values
    assert not constant_fill.isna().any(axis=None), "❌ `constant_fill` should not contain any NaN values"
    print("✅ `constant_fill` does not contain any NaN values")


def test_14(mean_per_cat:pd.DataFrame) -> None:
    """Test for exercise"""

    # Make sure its even a dataframe
    assert isinstance(mean_per_cat, pd.DataFrame), "❌ `mean_per_cat` is not a DataFrame"
    print("✅ `mean_per_cat` is a DataFrame")

    other = get_df()[['Stock','Price','Category']].groupby('Category').agg('mean')

    # Order doesnt matter -> use a set to compare columns and indices
    assert set(other.columns) == set(mean_per_cat.columns), f"`mean_per_cat` does not have the right columns"
    assert set(other.index) == set(mean_per_cat.index), f"`mean_per_cat` does not have the right indices"
    print("✅ `mean_per_cat` has the correct columns and indices")

    # Now that columns/indices match, we can use mean_per_cat.eq to compare each value
    assert all(mean_per_cat.eq(other)), "❌ Not every value in `mean_per_cat` is correct"
    print("✅ `mean_per_cat` has correct values")


def test_15(detailed:pd.DataFrame) -> None:
    """Test for exercise"""

    # Make sure its even a dataframe
    assert isinstance(detailed, pd.DataFrame), "❌ `detailed` is not a DataFrame"
    print("✅ `detailed` is a DataFrame")

    # First approach: just use a list in .agg
    try:
        other = get_df().groupby(by='Category')['Price'].agg(['count', 'max', 'mean', 'min'])

        # Order doesnt matter -> use a set to compare columns and indices
        assert set(other.columns) == set(detailed.columns), "❌ `detailed` does not have the right columns"
        assert set(other.index) == set(detailed.index), "❌ `detailed` does not have the right indices"

        # Now that columns/indices match, we can use detailed.eq to compare each value
        assert all(detailed.eq(other)), "❌ Not every value in `detailed` is correct"

    # Another approach: using a mapping to aggregate
    except AssertionError:
        other = get_df().groupby(by='Category').agg({'Price':['count', 'max', 'mean', 'min']})

        # Order doesnt matter -> use a set to compare columns and indices
        assert set(other.columns) == set(detailed.columns), "❌ `detailed` does not have the right columns"
        assert set(other.index) == set(detailed.index), "❌ `detailed` does not have the right indices"

        # Now that columns/indices match, we can use detailed.eq to compare each value
        assert all(detailed.eq(other)), "❌ Not every value in `detailed` is correct"

    print("✅ `detailed` has correct values")

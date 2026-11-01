# Separate data binding from SQL structure

## Source inspection

Collect the query text/expression and bindings at the real driver boundary. Trace raw ORM helpers, stored procedures and jobs that rebuild queries from stored values. A safe INSERT does not make a later interpolated SELECT safe. Keep dialect, database role and installed library context attached to the conclusion.

The package's SQLite training fixture contrasts these exact patterns:

```python
# deliberately vulnerable illustration with only synthetic fixture rows
sql = "SELECT id,name FROM catalog WHERE published=1 AND name LIKE '%" + q + "%'"
rows = db.execute(sql).fetchall()

# value binding for this SQLite value context
rows = db.execute(
    'SELECT id,name FROM catalog WHERE published=1 AND name LIKE ?',
    ('%' + q + '%',),
).fetchall()
```

The structural fixture value changes selected rows in the first path and remains a literal in the second. Merely obtaining a syntax error does not establish that effect. This repair addresses SQL syntax control; literal-versus-wildcard search semantics are a separate product requirement.

## Identifier and ordering path

A value placeholder is not a universal way to supply a column name, direction or operator. If the feature accepts a sort choice, inspect whether it selects from trusted constants or interpolates arbitrary source text:

```text
sort_map = {"newest": trusted_created_desc, "name": trusted_name_asc}
selected_structure = sort_map[validated_user_choice]
bind the remaining data values through the driver
```

Do not replace a closed structural map with a guessed escaping routine. Verify the actual database API and preserve intended valid sorting.

## Evidence to close

The minimal record has the original input, query/binding construction, controlled hidden/public row contrast and legitimate search control. Re-run the same data flow on the changed build; a patched frontend does not repair a server job. Database-wide extraction, arbitrary file access and long delays add no evidence needed for this controlled structural claim.

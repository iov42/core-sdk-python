Contributor Guide
=================

Thank you for your interest in improving this project.
This project is open-source under the `MIT license`_ and
welcomes contributions in the form of bug reports, feature requests, and pull requests.

Here is a list of important resources for contributors:

- `Source Code`_
- `Documentation`_
- `Issue Tracker`_
- `Code of Conduct`_

.. _MIT license: https://opensource.org/licenses/MIT
.. _Source Code: https://github.com/iov42/core-sdk-python
.. _Documentation: https://iov42-core-python.readthedocs.io/
.. _Issue Tracker: https://github.com/iov42/core-sdk-python/issues

How to report a bug
-------------------

Report bugs on the `Issue Tracker`_.

When filing an issue, make sure to answer these questions:

- Which operating system and Python version are you using?
- Which version of this project are you using?
- What did you do?
- What did you expect to see?
- What did you see instead?

The best way to get your bug fixed is to provide a test case,
and/or steps to reproduce the issue.


How to request a feature
------------------------

Request features on the `Issue Tracker`_.


How to set up your development environment
------------------------------------------

System requirements
^^^^^^^^^^^^^^^^^^^

You need a recent Linux, Unix or Mac system with bash_, curl_, and git_.

On Windows 10, enable the `Windows Subsystem for Linux`_ (WSL) and install the
Ubuntu 20.04 LTS distribution. Open Ubuntu from the Start Menu, and install
additional packages using the following commands:

.. code:: console

   $ sudo apt update
   $ sudo apt install -y build-essential curl git libbz2-dev \
     libffi-dev liblzma-dev libncurses5-dev libncursesw5-dev \
     libreadline-dev libsqlite3-dev libssl-dev llvm make \
     python-openssl wget xz-utils zlib1g-dev

.. note::
   When working in this project on Windows, configure your text editor or IDE
   to use only `UNIX-style line endings <https://en.wikipedia.org/wiki/Newline>`_
   (line feeds).

   The project contains a `.gitattributes <https://git-scm.com/book/en/Customizing-Git-Git-Attributes>`_
   file which enables end-of-line normalization for your entire working tree.
   Additionally, the Prettier_ code formatter converts line endings to line
   feeds. Windows-style line endings (CRLF) should therefore never make it into
   your Git repository.

   Nonetheless, configuring your editor for line feeds is recommended to avoid
   complaints from the pre-commit_ hook for Prettier.

.. _bash: https://www.gnu.org/software/bash/
.. _curl: https://curl.haxx.se/
.. _git: https://www.git-scm.com/
.. _Windows Subsystem for Linux: https://docs.microsoft.com/en-us/windows/wsl/install-win10
.. _Prettier: https://prettier.io/
.. _pre-commit: https://pre-commit.com/

Getting Python
^^^^^^^^^^^^^^

It is recommended to use pyenv_ for installing and managing Python versions.
Please refer to the documentation of this project for detailed installation and
usage instructions.

Install pyenv_ like this:

.. code:: console

   $ curl https://pyenv.run | bash

Add the following lines to your `~/.bashrc`:

.. code:: bash

   export PATH="$HOME/.pyenv/bin:$PATH"
   eval "$(pyenv init -)"
   eval "$(pyenv virtualenv-init -)"

Install the Python build dependencies for your platform, using one of the
commands listed in the `official instructions
<https://github.com/pyenv/pyenv/wiki/Common-build-problems>`_.

Install the latest point release of every supported Python version. This project
supports Python 3.6, 3.7, and 3.8.

.. code:: console

   $ pyenv install 3.6.12
   $ pyenv install 3.7.9
   $ pyenv install 3.8.5

.. _pyenv: https://github.com/pyenv/pyenv

Requirements
^^^^^^^^^^^^

.. note::
   It is recommended to use pipx_ to install Python tools which are not specific
   to a single project. Please refer to the official documentation for detailed
   installation and usage instructions. If you decide to skip pipx installation,
   use `pip install <https://pip.pypa.io/en/stable/reference/pip_install/>`_
   with the --user option instead.

You need the following tools:

- Poetry_
- Nox_

Install Poetry_ by downloading and running `get-poetry.py
<https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py>`_:

.. code:: console

   $ python get-poetry.sh

Install Nox_ using pipx:

.. code:: console

   $ pipx nox

Getting the project
^^^^^^^^^^^^^^^^^^^

Clone the project and change into the directory:

.. code:: console

    $ git clone git@github.com:iov42/core-sdk-python.git
    $ cd core-sdk-python

After creating your project, you can make the required Python versions
accessible in the project directory, using the following command:

.. code:: console

    $ pyenv local 3.8.5 3.7.9 3.6.12

The first version listed is the one used when you type plain ``python``. Every
version can be used by invoking ``python<major.minor>``. For example, use
``python3.7`` to invoke Python 3.7.

Select Python environment used for development and install the package with
development requirements:

.. code:: console

   $ poetry use 3.8
   $ poetry install

You can now run an interactive Python session, or the command-line interface:

.. code:: console

   $ poetry run python
   $ poetry run iov42

.. _pipx: https://pipxproject.github.io/pipx/
.. _Poetry: https://python-poetry.org/
.. _Nox: https://nox.thea.codes/

How to test the project
-----------------------

Run the full test suite:

.. code:: console

   $ nox -r

List the available Nox sessions:

.. code:: console

   $ nox --list-sessions

You can also run a specific Nox session.
For example, invoke the unit test suite like this:

.. code:: console

   $ nox -r --session=tests

Unit tests are located in the ``tests`` directory,
and are written using the pytest_ testing framework.

.. _pytest: https://pytest.readthedocs.io/


How to submit changes
---------------------

Open a `pull request`_ to submit changes to this project.

Your pull request needs to meet the following guidelines for acceptance:

- The Nox test suite must pass without errors and warnings.
- Include unit tests. This project maintains 100% code coverage.
- If your changes add functionality, update the documentation accordingly.

Feel free to submit early, though—we can always iterate on this.

To run linting and code formatting checks before commiting your change, you can install pre-commit as a Git hook by running the following command:

.. code:: console

   $ nox --session=pre-commit -- install

It is recommended to open an issue before starting work on anything.
This will allow a chance to talk it over with the owners and validate your approach.

.. _pull request: https://github.com/iov42/core-sdk-python/pulls
.. github-only
.. _Code of Conduct: CODE_OF_CONDUCT.rst

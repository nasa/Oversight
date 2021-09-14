import pytest
import os
import time


@pytest.fixture(scope="session")
def docker_compose_files(request):
    """
    Get an absolute path to the  `docker-compose.yml` file. Override this
    fixture in your tests if you need a custom location.

    Returns:
        string: the path of the `docker-compose.yml` file

    """
    t0 = time.perf_counter()
    print("Session Scope Starting at:{}".format(str(t0)))
    docker_compose_path = os.path.join(
        str(request.config.invocation_dir), "docker-compose.yml"
    )
    # LOGGER.info("docker-compose path: %s", docker_compose_path)

    def my_own_session_run_at_end():
            t1 = time.perf_counter()
            delta = t1-t0
            print('Session Scope Ending at:{}, delta={}'.format(str(t1), str(delta)))
    request.addfinalizer(my_own_session_run_at_end)

    return [docker_compose_path]
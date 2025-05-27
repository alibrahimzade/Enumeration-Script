import multiprocessing

def overload():
    while True:
        pass

if __name__ == "__main__":
    for _ in range(multiprocessing.cpu_count()):
        p = multiprocessing.Process(target=overload)
        p.start()

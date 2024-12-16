# # from ctfsolver import CTFSolver
# from app.ctfsolver.src.ctfsolver import CTFSolver

# # Create a CTFSolver object
# solver = CTFSolver()
# # print(solver.get_self_functions())
# print(
#     solver.get_functions_from_file(
#         "/home/figaro/Programms/Github_Projects/NikolasProjects/CTFSolverScript/app/ctfsolver/src/manager_file.py",
#         "prepare_space",
#     )
# )


# test_import.py
try:
    import ctfsolver
    print("ctfsolver imported successfully!")
except Exception as e:
    print(f"Error importing ctfsolver: {e}")
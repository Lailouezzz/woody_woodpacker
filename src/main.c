[[nodiscard("You mmust handle")]]
int main(int argc, char **argv, char **envp) {
	(void)(argc);
	(void)(argv);
	(void)(envp);
	typeof(argc) i;

	i = 1;
	auto k = i;
	++i;
	int a = i;
	return (k);
}

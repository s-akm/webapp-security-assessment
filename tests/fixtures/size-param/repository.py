class Repo:
    async def page(self, max_results: int = 50):
        return self.rows[:max_results]

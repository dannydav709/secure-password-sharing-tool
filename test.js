passwords = [
    {first: "hi",
    second: "bye"},

    {first:"one",
    second: "two"}
]

passwords.map(element => {
    element = {
        first: "changed",
        second: "changed"
    }
})

console.log(passwords)
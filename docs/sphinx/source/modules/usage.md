# Usage

## Initial 

To use a lot of the functionalities you need to run 

```bash 
ctfsolver init
```

This will create a config file  in `~/.config/ctfsolver`

where you need to fill in the following information: 

```json
{
  "directories": {
    "ctf_data": null,
    "documentation": null,
    "venvs": null,
    "downloads": null,
    "exclude": []
  },
  "structures": {
    "ctf_folder": ["data", "files", "payloads", "docs"]
  }
}
```

Where you need to fill out the relevant directories, which folders to be excluded ( this is for a future feature), and what kind of folder structure you want your ctf challenge to have. 

The folders files and payloads are essential if you don't want to change the functionalities of `automove`, `temp` and `run`. 

----

## ctfsolver --help


This will get you all the possible functions the cli tool can run 

```
ctfsolver help
```


### ctfsolver ctf 

#### ctfsolver ctf create 

```bash 
ctfsolver ctf create -s Site -c Category -n Name  
```



Will create the challenge ( as specified in the ctf_directory ) and will also create the folders 

#### ctfsolver ctf folders


If you just want to create the folders run : 

```bash 
folders
```

or 

```bash 
ctfsolver ctf folders
```



---

### ctfsolver templ 

I am used to a specific format for my challenges, so I have a function that auto creates the template 

```bash 
templ
```


----


### ctfsolver run 

Instead of always typing `python payloads/solution.py` I can just type

```bash 
run
```


----

### automove 


If you have declared where your download folder is, then automove can relate the files in your download folder with the category you are in right now or the name of the challenge and move the files in the `files` folder 


```bash 
ctfsolver ctf automove
```

`-y` to have to manually agree to move the file 


With `-d` in the `create` command you can do this process without having to navigate to the folder that the ctf is in. 



----


More functionality to the next update 
